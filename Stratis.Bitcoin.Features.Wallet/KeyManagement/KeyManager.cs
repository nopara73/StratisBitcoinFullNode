using NBitcoin;
using System;
using System.Collections.Generic;
using System.Text;
using ConcurrentCollections;
using System.Linq;
using System.Threading.Tasks;
using System.Threading;
using System.Security;

namespace Stratis.Bitcoin.Features.Wallet.KeyManagement
{
    /// <summary>
	/// BIP43, BIP44, BIP49 implementation
	/// </summary>
    public class KeyManager
    {
        // m / purpose' / coin_type' / account' / change / address_index
        public HdPurpose Purpose { get; }
        public KeyPath PurposePath
        {
            get
            {
                if (this.Purpose == HdPurpose.Bip44) return new KeyPath("m/44'");
                if (this.Purpose == HdPurpose.Bip49) return new KeyPath("m/49'");
                throw new NotSupportedException(this.Purpose.ToString());
            }
        }
        public Network CoinType { get; }
        public KeyPath CoinTypePath
        {
            get
            {
                // SLIP-0044 : Registered coin types for BIP-0044
                // https://github.com/satoshilabs/slips/blob/master/slip-0044.md
                if (this.CoinType == Network.Main) return this.PurposePath.Derive(0, true); // Bitcoin
                if (this.CoinType == Network.Main) return this.PurposePath.Derive(105, true); // Stratis
                else return this.PurposePath.Derive(1, true); ; // Testnet (all coins)
            }
        }

        public int CreationHeight { get; set; }
        private string WalletPassword { get; }

        public ConcurrentHashSet<HdAccount> Accounts { get; }
        public ConcurrentHashSet<HdPubKey> Keys { get; }

        public BitcoinEncryptedSecretNoEC EncryptedSecret { get; private set; }
        public byte[] ChainCode { get; private set; }
        private SemaphoreSlim InitializeSemaphore { get; }

        public KeyManager(string walletPassword, HdPurpose purpose, Network network, int creationHeight = 0)
        {
            this.WalletPassword = walletPassword ?? throw new ArgumentNullException(nameof(walletPassword));
            this.Purpose = purpose;
            this.CoinType = network ?? throw new ArgumentNullException(nameof(network));
            if (creationHeight < 0) throw new ArgumentException(nameof(creationHeight));
            this.CreationHeight = creationHeight;
            this.Accounts = new ConcurrentHashSet<HdAccount>();
            this.Keys = new ConcurrentHashSet<HdPubKey>();
            this.EncryptedSecret = null;
            this.ChainCode = null;
            this.InitializeSemaphore = new SemaphoreSlim(1, 1);
        }

        public async Task<HdPubKey> CreateNewKeyAsync(int accountIndex, bool isInternal, string label, CancellationToken cancel)
        {
            return await Task.Run(() =>
            {
                if (accountIndex < 0) throw new ArgumentOutOfRangeException(nameof(accountIndex));
                var account = this.Accounts.SingleOrDefault(x => x.Index == accountIndex);
                if (account == default(HdAccount))
                {
                    throw new InvalidOperationException("Account does not exist");
                }

                KeyPath path = null;
                PubKey pubKey = null;
                var index = 0;
                if (isInternal)
                {
                    HdPubKey prevHdPubKey = this.Keys.Where(x => x.IsInternal).OrderByDescending(x => x.Index).FirstOrDefault();
                    if (prevHdPubKey != default(HdPubKey))
                    {
                        index = prevHdPubKey.Index + 1;
                    }
                    path = account.InternalChainPath.Derive(index, false);
                    pubKey = account.InternalChainExtPubKey.Derive(index, false).PubKey;
                }
                else
                {
                    HdPubKey prevHdPubKey = this.Keys.Where(x => !x.IsInternal).OrderByDescending(x => x.Index).FirstOrDefault();
                    if (prevHdPubKey != default(HdPubKey))
                    {
                        index = prevHdPubKey.Index + 1;
                    }
                    path = account.ExternalChainPath.Derive(index, false);
                    pubKey = account.ExternalChainExtPubKey.Derive(index, false).PubKey;
                }

                var hdPubKey = new HdPubKey(this.CoinType, pubKey, path, label);

                this.Keys.Add(hdPubKey);

                return hdPubKey;
            }, cancel).ConfigureAwait(false);
        }
        
        public async Task<ExtPubKey> GetExtPubKeyAsync(KeyPath keyPath, string password, CancellationToken cancel)
        {
            return await Task.Run(() =>
            {
                if (password == null) throw new ArgumentNullException(nameof(password));
                if (keyPath == null) throw new ArgumentNullException(nameof(keyPath));
                if (password != this.WalletPassword) throw new SecurityException("Wrong password");

                var key = this.EncryptedSecret.GetKey(password);
                var extKey = new ExtKey(key, this.ChainCode);
                var accountExtPubKey = extKey.Derive(keyPath).Neuter();
                return accountExtPubKey;
            }, cancel).ConfigureAwait(false);
        }

        public async Task<ExtKey> GetExtKey(KeyPath keyPath, string password, CancellationToken cancel)
        {
            return await Task.Run(() =>
            {
                if (password == null) throw new ArgumentNullException(nameof(password));
                if (keyPath == null) throw new ArgumentNullException(nameof(keyPath));
                if (password != this.WalletPassword) throw new SecurityException("Wrong password");

                var key = this.EncryptedSecret.GetKey(password);
                var extKey = new ExtKey(key, this.ChainCode);
                var accountExtKey = extKey.Derive(keyPath);
                return accountExtKey;
            }, cancel).ConfigureAwait(false);
        }

        #region States

        /// <summary>
        /// Note: used keys cannot be updated
        /// </summary>
        public bool TryUpdateState (PubKey pubKey, HdKeyState state)
        {
            // used keys should never be updated
            // even if a tx falls out of the mempool, the tx and the scriptPubKey had been already seen by nodes
            HdPubKey hdPubKey = this.Keys
                .Where(x=>x.State != HdKeyState.Used)
                ?.SingleOrDefault(x => x.PubKey.Hash == pubKey.Hash);
            if(hdPubKey == default(HdPubKey))
            {
                return false;
            }
            if(hdPubKey.State == state)
            {
                return false;
            }
            hdPubKey.State = state;
            return true;
        }

        /// <summary>
        /// Note: used keys cannot be updated
        /// </summary>
        public bool TryUpdateState(BitcoinAddress address, HdKeyState state)
        {
            // used keys should never be updated
            // even if a tx falls out of the mempool, the tx and the scriptPubKey had been already seen by nodes
            HdPubKey hdPubKey = this.Keys
                .Where(x => x.State != HdKeyState.Used)
                ?.SingleOrDefault(x => 
                    x.P2pkhAddress == address
                    || x.P2wpkhAddress == address
                    || x.P2shOverP2wpkhAddress == address);
            if (hdPubKey == default(HdPubKey))
            {
                return false;
            }
            if (hdPubKey.State == state)
            {
                return false;
            }
            hdPubKey.State = state;
            return true;
        }

        /// <summary>
        /// Note: used keys cannot be updated
        /// </summary>
        public bool TryUpdateState(Script scriptPubKey, HdKeyState state)
        {
            // used keys should never be updated
            // even if a tx falls out of the mempool, the tx and the scriptPubKey had been already seen by nodes
            HdPubKey hdPubKey = this.Keys
                .Where(x => x.State != HdKeyState.Used)
                ?.SingleOrDefault(x =>
                    x.P2pkhScriptPubKey == scriptPubKey
                    || x.P2wpkhScriptPubKey == scriptPubKey
                    || x.P2shOverP2wpkhScriptPubKey == scriptPubKey);
            if (hdPubKey == default(HdPubKey))
            {
                return false;
            }
            if (hdPubKey.State == state)
            {
                return false;
            }
            hdPubKey.State = state;
            return true;
        }

        #endregion

        #region Initalization

        public async Task<Mnemonic> InitializeNewAsync(string mnemonicSalt, Wordlist wordlist, WordCount wordCount, CancellationToken cancel)
        {
            return await Task.Run(async () =>
            {
                await this.InitializeSemaphore.WaitAsync(cancel).ConfigureAwait(false);
                try
                {
                    if (this.EncryptedSecret != null) throw new InvalidOperationException($"{nameof(KeyManager)} is already initialized");
                    
                    if (mnemonicSalt == null) throw new ArgumentNullException(nameof(mnemonicSalt));
                    if (wordlist == null) throw new ArgumentNullException(nameof(wordlist));

                    var mnemonic = new Mnemonic(wordlist, wordCount);

                    ExtKey extKey = mnemonic.DeriveExtKey(mnemonicSalt);

                    this.EncryptedSecret = extKey.PrivateKey.GetEncryptedBitcoinSecret(this.WalletPassword, this.CoinType);
                    this.ChainCode = extKey.ChainCode;

                    return mnemonic;
                }
                finally
                {
                    this.InitializeSemaphore.SafeRelease();
                }
            }, cancel).ConfigureAwait(false);
        }

        public async Task InitializeFromMnemonicAsync(string mnemonicSalt, Mnemonic mnemonic, CancellationToken cancel)
        {
            await Task.Run(async () =>
            {
                await this.InitializeSemaphore.WaitAsync(cancel).ConfigureAwait(false);
                try
                {
                    if (this.EncryptedSecret != null) throw new InvalidOperationException($"{nameof(KeyManager)} is already initialized");
                    
                    if (mnemonicSalt == null) throw new ArgumentNullException(nameof(mnemonicSalt));
                    if (mnemonic == null) throw new ArgumentNullException(nameof(mnemonic));

                    ExtKey extKey = mnemonic.DeriveExtKey(mnemonicSalt);

                    this.EncryptedSecret = extKey.PrivateKey.GetEncryptedBitcoinSecret(this.WalletPassword, this.CoinType);
                    this.ChainCode = extKey.ChainCode;
                }
                finally
                {
                    this.InitializeSemaphore.SafeRelease();
                }
            }, cancel).ConfigureAwait(false);
        }

        public async Task InitializeFromExtKey(ExtKey extKey, CancellationToken cancel)
        {
            await Task.Run(async () =>
            {
                await this.InitializeSemaphore.WaitAsync(cancel).ConfigureAwait(false);
                try
                {
                    if (this.EncryptedSecret != null) throw new InvalidOperationException($"{nameof(KeyManager)} is already initialized");
                    
                    if (extKey == null) throw new ArgumentNullException(nameof(extKey));

                    this.EncryptedSecret = extKey.PrivateKey.GetEncryptedBitcoinSecret(this.WalletPassword, this.CoinType);
                    this.ChainCode = extKey.ChainCode;
                }
                finally
                {
                    this.InitializeSemaphore.SafeRelease();
                }
            }, cancel).ConfigureAwait(false);
        }

        #endregion

        #region Accounts

        public bool ContainsAccount(int index)
        {
            return this.Accounts.Any(x => x.Index == index);
        }
                
        public async Task<bool> TryAddAccountAsync(int index, string label, CancellationToken cancel)
        {
            if (label == null) return false;
            if(ContainsAccount(index))
            {
                return false;
            }

            var keyPath = this.CoinTypePath.Derive(index, true);
            var extPubKey = await GetExtPubKeyAsync(keyPath, this.WalletPassword, cancel);
            return this.Accounts.Add(new HdAccount(extPubKey, keyPath, label));
        }

        public async Task<bool> TryAddAccountAsync(string label, CancellationToken cancel)
        {
            if (label == null) return false;

            PubKey pubKey = this.EncryptedSecret.GetKey(this.WalletPassword).PubKey;
            var extPubKey = new ExtPubKey(pubKey, this.ChainCode);
            
            for (int i = 0; i <= this.Accounts.Count; i++)
            {
                if (!ContainsAccount(i))
                {
                    var keyPath = this.CoinTypePath.Derive(i, true);
                    ExtPubKey accountExtPubKey = await GetExtPubKeyAsync(keyPath, this.WalletPassword, cancel).ConfigureAwait(false);
                    return this.Accounts.Add(new HdAccount(accountExtPubKey, keyPath, label));
                }
            }
            throw new NotSupportedException(); // This should never happen
        }

        public bool TryRemoveAccount(HdAccount account)
        {
            if (account == null) return false;

            return this.Accounts.TryRemove(account);
        }

        public bool TryRemoveAccount(int index)
        {
            HdAccount account = this.Accounts.SingleOrDefault(x => x.Index == index);
            if (account == default(HdAccount)) return false;
            return this.Accounts.TryRemove(account);
        }

        public bool TryChangeAccountLabel(int index, string newLabel)
        { 
            if (newLabel == null) return false;
            var account = this.Accounts.SingleOrDefault(x=>x.Index == index);
            if (account == default(HdAccount)) return false;
            this.Accounts.TryRemove(account);
            return this.Accounts.Add(new HdAccount(account.ExtPubKey, account.Path, newLabel));
        }

        #endregion
    }
}
