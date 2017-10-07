using NBitcoin;
using Stratis.Bitcoin.Utilities.Extensions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Stratis.Bitcoin.Features.Wallet.KeyManagement
{
    public class Bip44KeyManager
    {
        public Network Network { get; }

        private KeyPath bip44CoinTypePath = null;
        public KeyPath Bip44CoinTypePath
        {
            get
            {
                if (this.bip44CoinTypePath == null)
                {
                    // SLIP-0044 : Registered coin types for BIP-0044
                    // https://github.com/satoshilabs/slips/blob/master/slip-0044.md
                    if (this.Network == Network.Main) this.bip44CoinTypePath = new KeyPath("44'/0'"); // Bitcoin
                    if (this.Network == Network.StratisMain) this.bip44CoinTypePath = new KeyPath("44'/105'"); // Stratis
                    else this.bip44CoinTypePath = new KeyPath("44'/1'"); // Testnet (all coins)
                }
                return this.bip44CoinTypePath;
            }
        }

        public DateTimeOffset CreationTime { get; set; }

        public BitcoinEncryptedSecretNoEC EncryptedSecret { get; private set; }
        public byte[] ChainCode { get; private set; }

        private Bip44Account[] accounts = null;
        private SemaphoreSlim AccountsSemaphore { get; } = new SemaphoreSlim(1, 1);

        public Bip44KeyManager(Network network, DateTimeOffset creationTime)
        {
            this.Network = network ?? throw new ArgumentNullException(nameof(network));
            this.CreationTime = creationTime;
        }

        #region Initialization

        public bool IsSeedInitialized
        {
            get
            {
                return this.EncryptedSecret != null && this.ChainCode != null;
            }
        }

        public bool IsAccountsInitialized
        {
            get
            {
                return this.accounts != null;
            }
        }

        private SemaphoreSlim InitializeSemaphore { get; } = new SemaphoreSlim(1, 1);

        public void InitializeAccounts(params Bip44Account[] accounts)
        {
            this.AccountsSemaphore.Wait();
            this.InitializeSemaphore.Wait();
            try
            {
                if (accounts == null) throw new ArgumentNullException(nameof(accounts));
                if (this.IsAccountsInitialized) throw new InvalidOperationException("Accounts are already initialized");

                for (var i = 0; i < accounts.Length; i++)
                {
                    if (i != accounts[i].Index) throw new ArgumentException("Wrong account indexing");
                }

                this.accounts = accounts;
            }
            finally
            {
                this.AccountsSemaphore.SafeRelease();
                this.InitializeSemaphore.SafeRelease();
            }
        }

        public void InitializeFrom(BitcoinEncryptedSecretNoEC encrypetedSecret, byte[] chainCode)
        {
            this.InitializeSemaphore.Wait();
            try
            {
                if (this.IsSeedInitialized) throw new InvalidOperationException("Seed is already initialized");

                this.EncryptedSecret = encrypetedSecret ?? throw new ArgumentNullException(nameof(encrypetedSecret));
                this.ChainCode = chainCode ?? throw new ArgumentNullException(nameof(chainCode));
            }
            finally
            {
                this.InitializeSemaphore.SafeRelease();
            }
        }

        public async Task InitializeFromAsync(ExtKey extKey, string walletPassword, CancellationToken cancel)
        {
            await this.InitializeSemaphore.WaitAsync(cancel).ConfigureAwait(false);
            try
            {
                if (extKey == null) throw new ArgumentNullException(nameof(extKey));
                if (walletPassword == null) throw new ArgumentNullException(nameof(walletPassword));
                if (this.IsSeedInitialized) throw new InvalidOperationException("Seed is already initialized");

                if (this.IsAccountsInitialized)
                {
                    await this.AccountsSemaphore.WaitAsync(cancel).ConfigureAwait(false);
                    try
                    {
                        foreach (var account in this.accounts)
                        {
                            if (extKey.Derive(account.Bip44KeyPath).Neuter() != account.ExtPubKey)
                            {
                                throw new InvalidOperationException($"Already initialized account does not match the provided {extKey}");
                            }
                        }
                    }
                    finally
                    {
                        this.AccountsSemaphore.SafeRelease();
                    }

                    this.ChainCode = extKey.ChainCode;
                    this.EncryptedSecret = extKey.PrivateKey.GetEncryptedBitcoinSecret(walletPassword, this.Network);
                }

            }
            finally
            {
                this.InitializeSemaphore.SafeRelease();
            }
        }

        public async Task InitializeFromAsync(string walletPassword, string mnemonicSalt, Mnemonic mnemonic, CancellationToken cancel)
        {
            await this.InitializeSemaphore.WaitAsync(cancel).ConfigureAwait(false);
            try
            {
                if (mnemonicSalt == null) throw new ArgumentNullException(nameof(mnemonicSalt));
                if (walletPassword == null) throw new ArgumentNullException(nameof(walletPassword));
                if (mnemonic == null) throw new ArgumentNullException(nameof(mnemonic));
                if (this.IsSeedInitialized) throw new InvalidOperationException("Seed is already initialized");

                ExtKey extKey = mnemonic.DeriveExtKey(mnemonicSalt);

                if (this.IsAccountsInitialized)
                {
                    await this.AccountsSemaphore.WaitAsync(cancel).ConfigureAwait(false);
                    try
                    {
                        foreach (var account in this.accounts)
                        {
                            if (extKey.Derive(account.Bip44KeyPath).Neuter() != account.ExtPubKey)
                            {
                                throw new InvalidOperationException($"Already initialized account does not match the provided {extKey}");
                            }
                        }
                    }
                    finally
                    {
                        this.AccountsSemaphore.SafeRelease();
                    }
                    
                    this.EncryptedSecret = extKey.PrivateKey.GetEncryptedBitcoinSecret(walletPassword, this.Network);
                    this.ChainCode = extKey.ChainCode;
                }

            }
            finally
            {
                this.InitializeSemaphore.SafeRelease();
            }
        }

        public async Task<Mnemonic> InitializeNewAsync(string walletPassword, string mnemonicSalt, Wordlist wordlist, WordCount wordCount, CancellationToken cancel)
        {
            await this.InitializeSemaphore.WaitAsync(cancel).ConfigureAwait(false);
            try
            {
                if (walletPassword == null) throw new ArgumentNullException(nameof(walletPassword));
                if (mnemonicSalt == null) throw new ArgumentNullException(nameof(mnemonicSalt));
                if (wordlist == null) throw new ArgumentNullException(nameof(wordlist));
                if (this.IsAccountsInitialized) throw new InvalidOperationException("Accounts are already initialized");
                if (this.IsSeedInitialized) throw new InvalidOperationException("Seed is already initialized");

                var mnemonic = new Mnemonic(wordlist, wordCount);
                ExtKey extKey = mnemonic.DeriveExtKey(mnemonicSalt);

                this.EncryptedSecret = extKey.PrivateKey.GetEncryptedBitcoinSecret(walletPassword, this.Network);
                this.ChainCode = extKey.ChainCode;

                return mnemonic;
            }
            finally
            {
                this.InitializeSemaphore.SafeRelease();
            }
        }


        #endregion        
    }
}
