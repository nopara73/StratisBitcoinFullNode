using NBitcoin;
using System;
using System.Collections.Generic;
using System.Text;
using ConcurrentCollections;
using System.Linq;
using System.Threading.Tasks;
using System.Threading;
using System.Security;
using Stratis.Bitcoin.Utilities.Extensions;

namespace Stratis.Bitcoin.Features.Wallet.KeyManagement
{
    /// <summary>
	/// BIP43, BIP44, BIP49 implementation
	/// </summary>
    public class KeyManager
    {
        // m / purpose' / coin_type' / account' / change / address_index
        public KeyPath PurposePath
        {
            get
            {
                return new KeyPath("m/44'");
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

        public ConcurrentHashSet<Bip44Account> Accounts { get; }

        public BitcoinEncryptedSecretNoEC EncryptedSecret { get; private set; }
        public byte[] ChainCode { get; private set; }
        private SemaphoreSlim InitializeSemaphore { get; }

        public bool IsDecrypted
        {
            get
            {
                return this.EncryptedSecret != null;
            }
        }

        public bool IsWatchOnly
        {
            get
            {
                return !this.IsDecrypted && this.Accounts != null && this.Accounts.Count() != 0;
            }
        }

        public KeyManager(Network network, int creationHeight = 0)
        {
            this.CoinType = network ?? throw new ArgumentNullException(nameof(network));
            if (creationHeight < 0) throw new ArgumentException(nameof(creationHeight));
            this.CreationHeight = creationHeight;
            this.Accounts = new ConcurrentHashSet<Bip44Account>();
            this.EncryptedSecret = null;
            this.ChainCode = null;
            this.InitializeSemaphore = new SemaphoreSlim(1, 1);
        }
        
        #region States

        public bool TryUpdateState (PubKey pubKey, Bip44KeyState state)
        {
            foreach(var key in this.Accounts.SelectMany(x => x.GetPubKeys(true, Order.Descending)))
            {
                if(key.PubKey == pubKey)
                {
                    key.State = state;
                    return true;
                }
            }
            foreach (var key in this.Accounts.SelectMany(x => x.GetPubKeys(false, Order.Descending)))
            {
                if (key.PubKey == pubKey)
                {
                    key.State = state;
                    return true;
                }
            }
            return false;
        }

        public bool TryUpdateState(BitcoinAddress address, Bip44KeyState state)
        {
            foreach (var key in this.Accounts.SelectMany(x => x.GetPubKeys(true, Order.Descending)))
            {
                if (key.P2pkhAddress == address || key.P2wpkhAddress == address || key.P2shOverP2wpkhAddress == address)
                {
                    key.State = state;
                    return true;
                }
            }
            foreach (var key in this.Accounts.SelectMany(x => x.GetPubKeys(false, Order.Descending)))
            {
                if (key.P2pkhAddress == address || key.P2wpkhAddress == address || key.P2shOverP2wpkhAddress == address)
                {
                    key.State = state;
                    return true;
                }
            }
            return false;
        }

        public bool TryUpdateState(Script script, Bip44KeyState state)
        {
            foreach (var key in this.Accounts.SelectMany(x => x.GetPubKeys(true, Order.Descending)))
            {
                if (key.P2pkScript == script || key.P2pkhScript == script || key.P2wpkhScript == script || key.P2shOverP2wpkhScript == script)
                {
                    key.State = state;
                    return true;
                }
            }
            foreach (var key in this.Accounts.SelectMany(x => x.GetPubKeys(false, Order.Descending)))
            {
                if (key.P2pkScript == script || key.P2pkhScript == script || key.P2wpkhScript == script || key.P2shOverP2wpkhScript == script)
                {
                    key.State = state;
                    return true;
                }
            }
            return false;
        }

        #endregion

        #region Initalization

        public async Task<Mnemonic> InitializeNewAsync(string walletPassword, string mnemonicSalt, Wordlist wordlist, WordCount wordCount, CancellationToken cancel)
        {
            return await Task.Run(async () =>
            {
                await this.InitializeSemaphore.WaitAsync(cancel).ConfigureAwait(false);
                try
                {
                    if (this.IsDecrypted) throw new InvalidOperationException($"{nameof(KeyManager)} is already initialized");
                    
                    if (mnemonicSalt == null) throw new ArgumentNullException(nameof(mnemonicSalt));
                    if (wordlist == null) throw new ArgumentNullException(nameof(wordlist));

                    var mnemonic = new Mnemonic(wordlist, wordCount);

                    ExtKey extKey = mnemonic.DeriveExtKey(mnemonicSalt);

                    this.EncryptedSecret = extKey.PrivateKey.GetEncryptedBitcoinSecret(walletPassword, this.CoinType);
                    this.ChainCode = extKey.ChainCode;

                    return mnemonic;
                }
                finally
                {
                    this.InitializeSemaphore.SafeRelease();
                }
            }, cancel).ConfigureAwait(false);
        }

        public async Task InitializeFromMnemonicAsync(string walletPassword, string mnemonicSalt, Mnemonic mnemonic, CancellationToken cancel)
        {
            await Task.Run(async () =>
            {
                await this.InitializeSemaphore.WaitAsync(cancel).ConfigureAwait(false);
                try
                {
                    if (this.IsDecrypted) throw new InvalidOperationException($"{nameof(KeyManager)} is already initialized");
                    
                    if (mnemonicSalt == null) throw new ArgumentNullException(nameof(mnemonicSalt));
                    if (mnemonic == null) throw new ArgumentNullException(nameof(mnemonic));

                    ExtKey extKey = mnemonic.DeriveExtKey(mnemonicSalt);

                    this.EncryptedSecret = extKey.PrivateKey.GetEncryptedBitcoinSecret(walletPassword, this.CoinType);
                    this.ChainCode = extKey.ChainCode;
                }
                finally
                {
                    this.InitializeSemaphore.SafeRelease();
                }
            }, cancel).ConfigureAwait(false);
        }

        public async Task InitializeFromExtKey(string walletPassword, ExtKey extKey, CancellationToken cancel)
        {
            await Task.Run(async () =>
            {
                await this.InitializeSemaphore.WaitAsync(cancel).ConfigureAwait(false);
                try
                {
                    if (this.IsDecrypted) throw new InvalidOperationException($"{nameof(KeyManager)} is already initialized");
                    
                    if (extKey == null) throw new ArgumentNullException(nameof(extKey));

                    this.EncryptedSecret = extKey.PrivateKey.GetEncryptedBitcoinSecret(walletPassword, this.CoinType);
                    this.ChainCode = extKey.ChainCode;
                }
                finally
                {
                    this.InitializeSemaphore.SafeRelease();
                }
            }, cancel).ConfigureAwait(false);
        }

        public void InitializeWatchOnly(IEnumerable<Bip44Account> accounts, IEnumerable<Bip44PubKey> keys)
        {
            if (this.IsDecrypted) throw new InvalidOperationException($"{nameof(KeyManager)} is already initialized");
            if(this.IsWatchOnly) if (this.IsDecrypted) throw new InvalidOperationException($"{nameof(KeyManager)} is already initialized");
            foreach (var account in accounts)
            {
                this.Accounts.Add(account);
            }
        }

        #endregion

        #region Accounts

        public bool ContainsAccount(int index)
        {
            return this.Accounts.Any(x => x.Index == index);
        }

        public bool ContainsAccount(string label)
        {
            return this.Accounts.Any(x => x.Label == label);
        }

        public async Task<bool> TryAddAccountAsync(string walletPassword, string label, CancellationToken cancel)
        {
            return await Task.Run(() =>
            {
                if (label == null) return false;

                Key key = this.EncryptedSecret.GetKey(walletPassword);
                var extKey = new ExtKey(key, this.ChainCode);

                for (int i = 0; i <= this.Accounts.Count; i++)
                {
                    if (!ContainsAccount(i))
                    {
                        var keyPath = this.CoinTypePath.Derive(i, true);
                        ExtPubKey accountExtPubKey = extKey.Derive(keyPath).Neuter();
                        return this.Accounts.Add(new Bip44Account(accountExtPubKey, keyPath, this.CoinType, label));
                    }
                }
                throw new NotSupportedException(); // This should never happen
            }, cancel).ConfigureAwait(false);
        }

        public bool TryChangeAccountLabel(int index, string newLabel)
        { 
            if (newLabel == null) return false;
            var account = this.Accounts.SingleOrDefault(x=>x.Index == index);
            if (account == default(Bip44Account)) return false;
            this.Accounts.TryRemove(account);
            return this.Accounts.Add(new Bip44Account(account.ExtPubKey, account.Bip44KeyPath, this.CoinType, newLabel));
        }

        /// <summary>
        /// Labels are not unique, so all oldLabel match will be changed
        /// </summary>
        public bool TryChangeAccountLabels(string oldLabel, string newLabel)
        {
            if (oldLabel == null) return false;
            if (newLabel == null) return false;
            var accounts = this.Accounts.Where(x => x.Label == oldLabel).Select(x=>x).ToList();
            if (accounts.Count() == 0) return false;
            foreach(var account in accounts)
            {
                account.Label = newLabel;
            }
            return true;
        }

        #endregion
    }
}
