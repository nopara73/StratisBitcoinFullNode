using NBitcoin;
using Newtonsoft.Json;
using Stratis.Bitcoin.Utilities.Extensions;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Stratis.Bitcoin.Features.Wallet.KeyManagement
{
    public class Bip44KeyManager
    {
        public Network Network { get; private set; }

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

        public void InitializeAccounts(Network network, DateTimeOffset creationTime, params Bip44Account[] accounts)
        {
            this.AccountsSemaphore.Wait();
            this.InitializeSemaphore.Wait();
            try
            {
                this.Network = network ?? throw new ArgumentNullException(nameof(network));
                if (accounts == null) throw new ArgumentNullException(nameof(accounts));
                if (this.IsAccountsInitialized) throw new InvalidOperationException("Accounts are already initialized");

                for (var i = 0; i < accounts.Length; i++)
                {
                    if (i != accounts[i].Index) throw new ArgumentException("Wrong account indexing");
                }
                this.CreationTime = creationTime;

                this.accounts = accounts;
            }
            finally
            {
                this.AccountsSemaphore.SafeRelease();
                this.InitializeSemaphore.SafeRelease();
            }
        }

        public void InitializeSeedFromEncryptedSecret(BitcoinEncryptedSecretNoEC encrypetedSecret, byte[] chainCode)
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

        public async Task InitializeSeedFromExtKeyAsync(ExtKey extKey, string walletPassword, CancellationToken cancel)
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

        public async Task InitializeSeedFromMnemonicAsync(string walletPassword, string mnemonicSalt, Mnemonic mnemonic, CancellationToken cancel)
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

        public async Task InitializeFullyFromJsonAsync(string jsonString, CancellationToken cancel)
        {
            await Task.Run(() =>
            {
                if (jsonString == null) throw new ArgumentNullException(nameof(jsonString));
                if (this.IsAccountsInitialized) throw new InvalidOperationException("Accounts are already initialized");
                if (this.IsSeedInitialized) throw new InvalidOperationException("Seed is already initialized");

                var keyManager = JsonConvert.DeserializeObject<Bip44KeyManager>(jsonString);
                InitializeAccounts(keyManager.Network, keyManager.CreationTime, keyManager.accounts);
                InitializeSeedFromEncryptedSecret(keyManager.EncryptedSecret, keyManager.ChainCode);
            }, cancel).ConfigureAwait(false);
        }

        public async Task InitializeFullyFromEncyptedJsonAsync(string encryptedJsonString, string encryptionPassword, CancellationToken cancel)
        {
            string jsonString = StringCipher.Decrypt(encryptedJsonString, encryptionPassword);
            await InitializeFullyFromJsonAsync(jsonString, cancel).ConfigureAwait(false);
        }
        
        public async Task InitializeFullyFromFileAsync(string filePath, CancellationToken cancel)
        {
            string jsonString = File.ReadAllText(filePath, Encoding.UTF8);
            await InitializeFullyFromJsonAsync(jsonString, cancel).ConfigureAwait(false);
        }

        public async Task InitializeFullyFromEncyptedFileAsync(string filePath, string encryptionPassword, CancellationToken cancel)
        {
            string encyptedJsonString = File.ReadAllText(filePath, Encoding.UTF8);
            await InitializeFullyFromEncyptedJsonAsync(encyptedJsonString, encryptionPassword, cancel).ConfigureAwait(false);
        }

        public async Task<Mnemonic> InitializeNewAsync(Network network, DateTimeOffset creationTime, string walletPassword, string mnemonicSalt, Wordlist wordlist, WordCount wordCount, CancellationToken cancel)
        {
            await this.InitializeSemaphore.WaitAsync(cancel).ConfigureAwait(false);
            try
            {
                this.Network = network ?? throw new ArgumentNullException(nameof(network));
                if (walletPassword == null) throw new ArgumentNullException(nameof(walletPassword));
                if (mnemonicSalt == null) throw new ArgumentNullException(nameof(mnemonicSalt));
                if (wordlist == null) throw new ArgumentNullException(nameof(wordlist));
                if (this.IsAccountsInitialized) throw new InvalidOperationException("Accounts are already initialized");
                if (this.IsSeedInitialized) throw new InvalidOperationException("Seed is already initialized");
                this.CreationTime = creationTime;

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

        #region OperationsOnAccountsCollection
        
        private Bip44Account[] accounts = null;
        private SemaphoreSlim AccountsSemaphore { get; } = new SemaphoreSlim(1, 1);

        public async Task<Bip44Account> CreateAccountAsync(string walletPassword, string label, CancellationToken cancel)
        {
            if (label == null) throw new ArgumentNullException(nameof(label));
            if (walletPassword == null) throw new ArgumentNullException(nameof(walletPassword));
            if (this.IsSeedInitialized) throw new InvalidOperationException("Seed is already initialized");
            ExtKey extKey = new ExtKey(this.EncryptedSecret.GetKey(walletPassword), this.ChainCode);

            await this.AccountsSemaphore.WaitAsync(cancel).ConfigureAwait(false);
            try
            {
                int index;
                if (this.accounts == null)
                {
                    this.accounts = new Bip44Account[1];
                    index = 0;
                }
                else
                {
                    index = this.accounts.Length - 1;
                    Array.Resize(ref this.accounts, this.accounts.Length + 1);
                }

                KeyPath keyPath = this.Bip44CoinTypePath.Derive(index, true);
                ExtPubKey extPubKey = extKey.Derive(keyPath).Neuter();
                this.accounts[index] = new Bip44Account(extPubKey, keyPath, this.Network, label);
                return this.accounts[index];
            }
            finally
            {
                this.AccountsSemaphore.SafeRelease();
            }            
        }

        public IEnumerable<Bip44Account> GetAccounts()
        {
            this.AccountsSemaphore.Wait();
            try
            {
                if (this.accounts == null) yield break;
                for (var i = 0; i < this.accounts.Length; i++)
                {
                    yield return this.accounts[i];
                }
            }
            finally
            {
                this.AccountsSemaphore.SafeRelease();
            }
        }

        public IEnumerable<Bip44Account> GetAccounts(string label)
        {
            if (label == null) throw new ArgumentNullException(nameof(label));
            this.AccountsSemaphore.Wait();
            try
            {
                if (this.accounts == null) yield break;
                for (var i = 0; i < this.accounts.Length; i++)
                {
                    if (this.accounts[i].Label == label)
                    {
                        yield return this.accounts[i];
                    }
                }
            }
            finally
            {
                this.AccountsSemaphore.SafeRelease();
            }
        }

        /// <returns>null if account hasn't been created</returns>
        public Bip44Account TryGetAccount(int index)
        {
            if (index < 0) throw new ArgumentOutOfRangeException($"{nameof(index)} cannot be smaller than 0");
            this.AccountsSemaphore.Wait();
            try
            {
                if (this.accounts == null || index >= this.accounts.Length)
                {
                    return null;
                }
                return this.accounts[index];
            }
            finally
            {
                this.AccountsSemaphore.SafeRelease();
            }
        }

        #endregion

        #region LabelOperationsOnAccounts

        public bool TryUpdateLabel(int index, string newLabel)
        {
            if (newLabel == null) throw new ArgumentNullException(nameof(newLabel));
            if (index < 0) throw new ArgumentOutOfRangeException($"{nameof(index)} cannot be smaller than 0");
            this.AccountsSemaphore.Wait();
            try
            {
                if (this.accounts == null || index >= this.accounts.Length)
                {
                    return false;
                }

                string oldLabel = this.accounts[index].Label;
                if (oldLabel == newLabel) return false;
                this.accounts[index].Label = newLabel;
                return true;
            }
            finally
            {
                this.AccountsSemaphore.SafeRelease();
            }
        }

        public bool TryUpdateLabels(string oldLabel, string newLabel)
        {
            if (newLabel == null) throw new ArgumentNullException(nameof(newLabel));
            if (oldLabel == null) throw new ArgumentNullException(nameof(oldLabel));
            if (oldLabel == newLabel) return false;
            var modifiedAtLeastOne = false;

            this.AccountsSemaphore.Wait();
            try
            {
                if (this.accounts != null)
                {
                    foreach (Bip44Account account in this.accounts)
                    {
                        if (account.Label == oldLabel)
                        {
                            account.Label = newLabel;
                            modifiedAtLeastOne = true;
                        }
                    }
                }
            }
            finally
            {
                this.AccountsSemaphore.SafeRelease();      
            }

            return modifiedAtLeastOne;
        }

        #endregion

        #region Serialization

        public async Task<string> ToJsonStringAsync(CancellationToken cancel)
        {
            return await Task.Run(() => 
            {
                return JsonConvert.SerializeObject(this);
            }, cancel).ConfigureAwait(false);
        }

        public async Task<string> ToEncyptedJsonAsync(string encryptionPassword, CancellationToken cancel)
        {
            string jsonString = await ToJsonStringAsync(cancel).ConfigureAwait(false);
            return StringCipher.Encrypt(jsonString, encryptionPassword);
        }

        public async Task ToFileAsync(string filePath, CancellationToken cancel)
        {
            File.WriteAllText(filePath,
                await ToJsonStringAsync(cancel).ConfigureAwait(false),
                Encoding.UTF8);
        }

        public async Task ToEncyptedFileAsync(string filePath, string encryptionPassword, CancellationToken cancel)
        {
            File.WriteAllText(filePath,
                await ToEncyptedJsonAsync(encryptionPassword, cancel).ConfigureAwait(false),
                Encoding.UTF8);
        }

        #endregion
    }
}
