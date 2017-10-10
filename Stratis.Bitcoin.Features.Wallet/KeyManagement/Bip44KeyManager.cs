using NBitcoin;
using NBitcoin.JsonConverters;
using Newtonsoft.Json;
using Stratis.Bitcoin.Features.Wallet.JsonConverters;
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
    [JsonObject(MemberSerialization.OptIn)]
    public class Bip44KeyManager
    {
        [JsonProperty(PropertyName = "network")]
        [JsonConverter(typeof(NetworkConverter))]
        public Network Network { get; private set; }
        [JsonProperty(PropertyName = "creationTime")]
        [JsonConverter(typeof(DateTimeOffsetConverter))]
        public DateTimeOffset CreationTime { get; set; }

        [JsonProperty(PropertyName = "encryptedSecret")]
        [JsonConverter(typeof(BitcoinEncryptedSecretNoECConverter))]
        public BitcoinEncryptedSecretNoEC EncryptedSecret { get; private set; }
        [JsonProperty(PropertyName = "chainCode")]
        [JsonConverter(typeof(ByteArrayConverter))]
        public byte[] ChainCode { get; private set; }

        [JsonProperty(PropertyName = "accounts")]
        private Bip44Account[] accounts = null;

        private KeyPath bip44CoinTypePath = null;
        public KeyPath GetBip44CoinTypePath()
        {
            if (this.bip44CoinTypePath == null)
            {
                // SLIP-0044 : Registered coin types for BIP-0044
                // https://github.com/satoshilabs/slips/blob/master/slip-0044.md
                if (this.Network == Network.Main) this.bip44CoinTypePath = new KeyPath("44'/0'"); // Bitcoin
                else if (this.Network == Network.StratisMain) this.bip44CoinTypePath = new KeyPath("44'/105'"); // Stratis
                else this.bip44CoinTypePath = new KeyPath("44'/1'"); // Testnet (all coins)
            }
            return this.bip44CoinTypePath;
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

        public void InitializeAccounts(Network network, params Bip44Account[] accounts)
        {
            this.AccountsSemaphore.Wait();
            this.InitializeSemaphore.Wait();
            try
            {
                if (accounts == null) throw new ArgumentNullException(nameof(accounts));
                if (network == null) throw new ArgumentNullException(nameof(network));
                if (this.Network == null) this.Network = network;
                else if (this.Network != network) throw new ArgumentException(nameof(network));
                if (this.IsAccountsInitialized) throw new InvalidOperationException("Accounts are already initialized");

                for (var i = 0; i < accounts.Length; i++)
                {
                    if (i != accounts[i].GetIndex()) throw new ArgumentException("Wrong account indexing");
                }

                this.accounts = accounts;
            }
            finally
            {
                this.AccountsSemaphore.SafeRelease();
                this.InitializeSemaphore.SafeRelease();
            }
        }

        public void InitializeSeedFromEncryptedSecret(Network network, BitcoinEncryptedSecretNoEC encrypetedSecret, byte[] chainCode)
        {
            this.InitializeSemaphore.Wait();
            try
            {
                if (this.IsSeedInitialized) throw new InvalidOperationException("Seed is already initialized");
                if (network == null) throw new ArgumentNullException(nameof(network));
                if (this.Network == null) this.Network = network;
                else if (this.Network != network) throw new ArgumentException(nameof(network));

                this.EncryptedSecret = encrypetedSecret ?? throw new ArgumentNullException(nameof(encrypetedSecret));
                this.ChainCode = chainCode ?? throw new ArgumentNullException(nameof(chainCode));
            }
            finally
            {
                this.InitializeSemaphore.SafeRelease();
            }
        }

        public async Task InitializeSeedFromExtKeyAsync(Network network, ExtKey extKey, string walletPassword, CancellationToken cancel)
        {
            await this.InitializeSemaphore.WaitAsync(cancel).ConfigureAwait(false);
            try
            {
                if (extKey == null) throw new ArgumentNullException(nameof(extKey));
                if (walletPassword == null) throw new ArgumentNullException(nameof(walletPassword));
                if (network == null) throw new ArgumentNullException(nameof(network));
                if (this.Network == null) this.Network = network;
                else if (this.Network != network) throw new ArgumentException(nameof(network));
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

        public async Task InitializeSeedFromMnemonicAsync(Network network, string walletPassword, string mnemonicSalt, Mnemonic mnemonic, CancellationToken cancel)
        {
            await this.InitializeSemaphore.WaitAsync(cancel).ConfigureAwait(false);
            try
            {
                if (mnemonicSalt == null) throw new ArgumentNullException(nameof(mnemonicSalt));
                if (walletPassword == null) throw new ArgumentNullException(nameof(walletPassword));
                if (mnemonic == null) throw new ArgumentNullException(nameof(mnemonic));
                if (network == null) throw new ArgumentNullException(nameof(network));
                if (this.Network == null) this.Network = network;
                else if (this.Network != network) throw new ArgumentException(nameof(network));
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

        public async Task<Mnemonic> InitializeNewAsync(Network network, string walletPassword, string mnemonicSalt, Wordlist wordlist, WordCount wordCount, CancellationToken cancel)
        {
            await this.InitializeSemaphore.WaitAsync(cancel).ConfigureAwait(false);
            try
            {
                if (walletPassword == null) throw new ArgumentNullException(nameof(walletPassword));
                if (mnemonicSalt == null) throw new ArgumentNullException(nameof(mnemonicSalt));
                this.Network = network ?? throw new ArgumentNullException(nameof(network));
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

        #region OperationsOnAccountsCollection
        
        private SemaphoreSlim AccountsSemaphore { get; } = new SemaphoreSlim(1, 1);

        public async Task CreateAccountAsync(string walletPassword, string label, CancellationToken cancel)
        {
            if (label == null) throw new ArgumentNullException(nameof(label));
            if (walletPassword == null) throw new ArgumentNullException(nameof(walletPassword));
            if (!this.IsSeedInitialized) throw new InvalidOperationException("Seed is not yet initialized");
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

                KeyPath keyPath = this.GetBip44CoinTypePath().Derive(index, true);
                ExtPubKey extPubKey = extKey.Derive(keyPath).Neuter();
                this.accounts[index] = new Bip44Account(extPubKey, keyPath, this.Network, label);
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
        public async Task ToFileAsync(string filePath, CancellationToken cancel)
        {
            await Task.Run(() =>
            {
                if (filePath == null) throw new ArgumentNullException(nameof(filePath));

                var settings = new JsonSerializerSettings
                {
                    NullValueHandling = NullValueHandling.Ignore
                };

                string jsonString = JsonConvert.SerializeObject(this, Formatting.Indented, settings);
                File.WriteAllText(filePath,
                jsonString,
                Encoding.UTF8);
            }, cancel).ConfigureAwait(false);
        }

        public async Task ToEncyptedFileAsync(string filePath, string encryptionPassword, CancellationToken cancel)
        {
            await Task.Run(() =>
            {
                if (filePath == null) throw new ArgumentNullException(nameof(filePath));
                if (encryptionPassword == null) throw new ArgumentNullException(nameof(encryptionPassword));

                var settings = new JsonSerializerSettings
                {
                    NullValueHandling = NullValueHandling.Ignore
                };

                File.WriteAllText(filePath,
                StringCipher.Encrypt(JsonConvert.SerializeObject(this, Formatting.None, settings), encryptionPassword),
                Encoding.UTF8);
            }, cancel).ConfigureAwait(false);
        }

        public async Task InitializeFullyFromFileAsync(string filePath, CancellationToken cancel)
        {
            await Task.Run(() =>
            {
                if (filePath == null) throw new ArgumentNullException(nameof(filePath));
                if (this.IsAccountsInitialized) throw new InvalidOperationException("Accounts are already initialized");
                if (this.IsSeedInitialized) throw new InvalidOperationException("Seed is already initialized");

                var settings = new JsonSerializerSettings
                {
                    NullValueHandling = NullValueHandling.Ignore
                };

                string jsonString = File.ReadAllText(filePath, Encoding.UTF8);
                var keyManager = JsonConvert.DeserializeObject<Bip44KeyManager>(jsonString, settings);
                InitializeAccounts(keyManager.Network, keyManager.accounts);
                InitializeSeedFromEncryptedSecret(keyManager.Network, keyManager.EncryptedSecret, keyManager.ChainCode);
            }, cancel).ConfigureAwait(false);
        }

        public async Task InitializeFullyFromEncyptedFileAsync(string filePath, string encryptionPassword, CancellationToken cancel)
        {
            await Task.Run(() =>
            {
                if (filePath == null) throw new ArgumentNullException(nameof(filePath));
                if (encryptionPassword == null) throw new ArgumentNullException(nameof(encryptionPassword));
                if (this.IsAccountsInitialized) throw new InvalidOperationException("Accounts are already initialized");
                if (this.IsSeedInitialized) throw new InvalidOperationException("Seed is already initialized");

                var settings = new JsonSerializerSettings
                {
                    NullValueHandling = NullValueHandling.Ignore
                };

                string encryptedJsonString = File.ReadAllText(filePath, Encoding.UTF8);
                string jsonString = StringCipher.Decrypt(encryptedJsonString, encryptionPassword);
                var keyManager = JsonConvert.DeserializeObject<Bip44KeyManager>(jsonString, settings);
                InitializeAccounts(keyManager.Network, keyManager.accounts);
                InitializeSeedFromEncryptedSecret(keyManager.Network, keyManager.EncryptedSecret, keyManager.ChainCode);
            }, cancel).ConfigureAwait(false);
        }

        #endregion
    }
}
