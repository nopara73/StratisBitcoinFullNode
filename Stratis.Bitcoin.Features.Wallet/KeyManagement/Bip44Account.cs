using ConcurrentCollections;
using NBitcoin;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Stratis.Bitcoin.Features.Wallet.KeyManagement
{
    public class Bip44Account : IEquatable<Bip44Account>
    {
        public ExtPubKey ExtPubKey { get; }
        public KeyPath Bip44KeyPath { get; }
        public Network Network { get; }

        public string Label { get; set; }

        public Bip44Account(ExtPubKey extPubKey, KeyPath bip44KeyPath, Network network, string label)
        {
            this.ExtPubKey = extPubKey ?? throw new ArgumentNullException(nameof(extPubKey));
            this.Bip44KeyPath = bip44KeyPath ?? throw new ArgumentNullException(nameof(bip44KeyPath));
            this.Network = network ?? throw new ArgumentNullException(nameof(network));
            this.Label = label ?? throw new ArgumentNullException(nameof(label));
        }

        private ExtPubKey internalChainExtPubKey = null;
        public ExtPubKey InternalChainExtPubKey
        {
            get
            {
                return this.internalChainExtPubKey ?? (this.internalChainExtPubKey = this.ExtPubKey.Derive(1, false));
            }
        }

        private ExtPubKey externalChainExtPubKey = null;
        public ExtPubKey ExternalChainExtPubKey
        {
            get
            {
                return this.externalChainExtPubKey ?? (this.externalChainExtPubKey = this.ExtPubKey.Derive(0, false));
            }
        }

        private KeyPath internalChainKeyPath = null;
        public KeyPath InternalChainKeyPath
        {
            get
            {
                return this.internalChainKeyPath ?? (this.internalChainKeyPath = this.Bip44KeyPath.Derive(1, false));
            }
        }

        private KeyPath externalChainKeyPath = null;
        public KeyPath ExternalChainKeyPath
        {
            get
            {
                return this.externalChainKeyPath ?? (this.externalChainKeyPath = this.Bip44KeyPath.Derive(0, false));
            }
        }

        private int? index = null;
        public int Index
        {
            get
            {
                return (int)(this.index ?? (this.index = (int)(this.Bip44KeyPath.Indexes[2] - 2147483648)));
            }
        }

        #region KeyColletionOperations

        private Bip44PubKey[] internalPubKeys = null;
        private Bip44PubKey[] externalPubKeys = null;

        private object InternalPubKeysLock { get; } = new object();
        private object ExternalPubKeysLock { get; } = new object();

        public IEnumerable<Bip44PubKey> GetPubKeys(bool isInternal, Order order)
        {
            if(isInternal)
            {
                lock(this.InternalPubKeysLock)
                {
                    if (this.internalPubKeys == null) yield break;
                    if (order == Order.Ascending)
                    {
                        for (var i = 0; i < this.internalPubKeys.Length; i++)
                        {
                            yield return this.internalPubKeys[i];
                        }
                    }
                    else
                    {
                        for (var i = this.internalPubKeys.Length - 1; i >= 0; i--)
                        {
                            yield return this.internalPubKeys[i];
                        }
                    }
                }
            }
            else
            {
                lock (this.ExternalPubKeysLock)
                {
                    if (this.externalPubKeys == null) yield break;
                    if (order == Order.Ascending)
                    {
                        for (var i = 0; i < this.externalPubKeys.Length; i++)
                        {
                            yield return this.externalPubKeys[i];
                        }
                    }
                    else
                    {
                        for (var i = this.externalPubKeys.Length - 1; i >= 0; i--)
                        {
                            yield return this.externalPubKeys[i];
                        }
                    }
                }
            }
        }

        public IEnumerable<Bip44PubKey> CreatePubKeys(bool isInternal, string label, int count)
        {
            if (count <= 0) throw new ArgumentOutOfRangeException(nameof(count));

            if (isInternal)
            {
                lock (this.InternalPubKeysLock)
                {
                    int firstIndex;
                    if (this.internalPubKeys == null)
                    {
                        this.internalPubKeys = new Bip44PubKey[count];
                        firstIndex = 0;
                    }
                    else
                    {
                        firstIndex = this.internalPubKeys.Length - 1;
                        Array.Resize(ref this.internalPubKeys, this.internalPubKeys.Length + count);
                    }

                    for(var i = firstIndex; i < firstIndex + count; i++)
                    {
                        KeyPath keyPath = this.internalChainKeyPath.Derive(i, false);
                        PubKey pubKey = this.InternalChainExtPubKey.Derive(i, false).PubKey;
                        this.internalPubKeys[i] = new Bip44PubKey(pubKey, keyPath, this.Network, label, Bip44KeyState.Clean);
                        yield return this.internalPubKeys[i];
                    }
                }
            }
            else
            {
                lock (this.ExternalPubKeysLock)
                {
                    int firstIndex;
                    if (this.externalPubKeys == null)
                    {
                        this.externalPubKeys = new Bip44PubKey[count];
                        firstIndex = 0;
                    }
                    else
                    {
                        firstIndex = this.externalPubKeys.Length - 1;
                        Array.Resize(ref this.externalPubKeys, this.externalPubKeys.Length + count);
                    }

                    for (var i = firstIndex; i < firstIndex + count; i++)
                    {
                        KeyPath keyPath = this.ExternalChainKeyPath.Derive(i, false);
                        PubKey pubKey = this.ExternalChainExtPubKey.Derive(i, false).PubKey;
                        this.externalPubKeys[i] = new Bip44PubKey(pubKey, keyPath, this.Network, label, Bip44KeyState.Clean);
                        yield return this.externalPubKeys[i];
                    }
                }
            }
        }

        #endregion

        #region Equality

        // speedup
        private int? hashCode = null;
        private int HashCode
        {
            get
            {
                return (int)(this.hashCode ?? (this.hashCode = this.ExtPubKey.PubKey.Hash.GetHashCode()));
            }
        }

        // speedup
        private KeyId uniquePubKeyHash = null;
        private KeyId UniquePubKeyHash
        {
            get
            {
                return this.uniquePubKeyHash ?? (this.uniquePubKeyHash = this.ExtPubKey.PubKey.Hash);
            }
        }

        public override bool Equals(object obj) => obj is Bip44Account && this == (Bip44Account)obj;
        public bool Equals(Bip44Account other) => this == other;
        public override int GetHashCode()
        {
            return this.HashCode;
        }
        public static bool operator ==(Bip44Account x, Bip44Account y)
        {
            return x.UniquePubKeyHash == y.UniquePubKeyHash;
        }
        public static bool operator !=(Bip44Account x, Bip44Account y)
        {
            return !(x == y);
        }

        #endregion
    }
}
