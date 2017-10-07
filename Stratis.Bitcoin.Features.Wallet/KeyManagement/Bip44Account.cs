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

        #region OperationsOnPubKeyCollections

        private Bip44PubKey[] internalPubKeys = null;
        private Bip44PubKey[] externalPubKeys = null;

        private object InternalPubKeysLock { get; } = new object();
        private object ExternalPubKeysLock { get; } = new object();

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
        
        public IEnumerable<Bip44PubKey> GetPubKeys(bool isInternal, Order order)
        {
            if (isInternal)
            {
                lock (this.InternalPubKeysLock)
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

        public IEnumerable<Bip44PubKey> GetPubKeys()
        {
            foreach(var pubKey in GetPubKeys(false, Order.Ascending))
            {
                yield return pubKey;
            }
            foreach (var pubKey in GetPubKeys(true, Order.Ascending))
            {
                yield return pubKey;
            }
        }
        
        /// <returns>null if key hasn't been created</returns>
        public Bip44PubKey TryGetPubKey(bool isInternal, int index)
        {
            if (index < 0) throw new ArgumentOutOfRangeException($"{nameof(index)} cannot be smaller than 0");
            if (isInternal)
            {
                lock (this.InternalPubKeysLock)
                {
                    if (this.internalPubKeys == null || index >= this.internalPubKeys.Length)
                    {
                        return null;
                    }
                    return this.internalPubKeys[index];
                }
            }
            else
            {
                lock (this.ExternalPubKeysLock)
                {
                    if (this.externalPubKeys == null || index >= this.externalPubKeys.Length)
                    {
                        return null;
                    }
                    return this.externalPubKeys[index];
                }
            }
        }

        #endregion

        #region StateOperationsOnPubKeys

        public bool TryUpdateState(bool isInternal, int index, Bip44KeyState newState)
        {
            if (index < 0) throw new ArgumentOutOfRangeException($"{nameof(index)} cannot be smaller than 0");
            if (isInternal)
            {
                lock (this.InternalPubKeysLock)
                {
                    if (this.internalPubKeys == null || index >= this.internalPubKeys.Length)
                    {
                        return false;
                    }

                    Bip44KeyState oldState = this.internalPubKeys[index].State;
                    if (oldState == newState) return false;
                    this.internalPubKeys[index].State = newState;
                    return true;
                }
            }
            else
            {
                lock (this.ExternalPubKeysLock)
                {
                    if (this.externalPubKeys == null || index >= this.externalPubKeys.Length)
                    {
                        return false;
                    }
                    Bip44KeyState oldState = this.externalPubKeys[index].State;
                    if (oldState == newState) return false;
                    this.externalPubKeys[index].State = newState;
                    return true;
                }
            }
        }
        public bool TryUpdateState(PubKey pubKey, Bip44KeyState newState)
        {
            KeyId pubKeyHash = pubKey?.Hash;
            if (pubKeyHash == null) throw new ArgumentNullException(nameof(pubKey));

            lock (this.InternalPubKeysLock) lock (this.ExternalPubKeysLock)
                {
                    if (this.internalPubKeys == null && this.externalPubKeys == null) return false;
                    // Search by descending, newer key states will be more often modified
                    int startIterateFrom;
                    if (this.internalPubKeys == null) startIterateFrom = this.externalPubKeys.Length - 1;
                    else if (this.externalPubKeys == null) startIterateFrom = this.internalPubKeys.Length - 1;
                    else startIterateFrom = Math.Max(this.internalPubKeys.Length, this.externalPubKeys.Length) - 1;

                    for (var i = startIterateFrom; i >= 0; i--)
                    {
                        if (this.internalPubKeys != null && this.internalPubKeys.Length > i)
                        {
                            if (this.internalPubKeys[i].PubKeyHash == pubKeyHash)
                            {
                                Bip44KeyState oldState = this.internalPubKeys[i].State;
                                if (oldState == newState) return false;
                                this.internalPubKeys[i].State = newState;
                                return true;
                            }
                        }
                        if (this.externalPubKeys != null && this.externalPubKeys.Length > i)
                        {
                            if (this.externalPubKeys[i].PubKeyHash == pubKeyHash)
                            {
                                Bip44KeyState oldState = this.externalPubKeys[i].State;
                                if (oldState == newState) return false;
                                this.externalPubKeys[i].State = newState;
                                return true;
                            }
                        }
                    }
                }
            return false;
        }
        public bool TryUpdateState(BitcoinAddress address, Bip44KeyState newState)
        {
            if (address == null) throw new ArgumentNullException(nameof(address));

            lock (this.InternalPubKeysLock) lock (this.ExternalPubKeysLock)
                {
                    if (this.internalPubKeys == null && this.externalPubKeys == null) return false;
                    // Search by descending, newer key states will be more often modified
                    int startIterateFrom;
                    if (this.internalPubKeys == null) startIterateFrom = this.externalPubKeys.Length - 1;
                    else if (this.externalPubKeys == null) startIterateFrom = this.internalPubKeys.Length - 1;
                    else startIterateFrom = Math.Max(this.internalPubKeys.Length, this.externalPubKeys.Length) - 1;

                    for (var i = startIterateFrom; i >= 0; i--)
                    {
                        if (this.internalPubKeys != null && this.internalPubKeys.Length > i)
                        {
                            if (this.internalPubKeys[i].P2pkhAddress == address
                                || this.internalPubKeys[i].P2wpkhAddress == address
                                || this.internalPubKeys[i].P2shOverP2wpkhAddress == address)
                            {
                                Bip44KeyState oldState = this.internalPubKeys[i].State;
                                if (oldState == newState) return false;
                                this.internalPubKeys[i].State = newState;
                                return true;
                            }
                        }
                        if (this.externalPubKeys != null && this.externalPubKeys.Length > i)
                        {
                            if (this.externalPubKeys[i].P2pkhAddress == address
                                || this.externalPubKeys[i].P2wpkhAddress == address
                                || this.externalPubKeys[i].P2shOverP2wpkhAddress == address)
                            {
                                Bip44KeyState oldState = this.externalPubKeys[i].State;
                                if (oldState == newState) return false;
                                this.externalPubKeys[i].State = newState;
                                return true;
                            }
                        }
                    }
                }
            return false;
        }
        public bool TryUpdateState(Script script, Bip44KeyState newState)
        {
            if (script == null) throw new ArgumentNullException(nameof(script));

            lock (this.InternalPubKeysLock) lock (this.ExternalPubKeysLock)
                {
                    if (this.internalPubKeys == null && this.externalPubKeys == null) return false;
                    // Search by descending, newer key states will be more often modified
                    int startIterateFrom;
                    if (this.internalPubKeys == null) startIterateFrom = this.externalPubKeys.Length - 1;
                    else if (this.externalPubKeys == null) startIterateFrom = this.internalPubKeys.Length - 1;
                    else startIterateFrom = Math.Max(this.internalPubKeys.Length, this.externalPubKeys.Length) - 1;

                    for (var i = startIterateFrom; i >= 0; i--)
                    {
                        if (this.internalPubKeys != null && this.internalPubKeys.Length > i)
                        {
                            if (this.internalPubKeys[i].P2pkScript == script
                                || this.internalPubKeys[i].P2pkhScript == script
                                || this.internalPubKeys[i].P2wpkhScript == script
                                || this.internalPubKeys[i].P2shOverP2wpkhScript == script)
                            {
                                Bip44KeyState oldState = this.internalPubKeys[i].State;
                                if (oldState == newState) return false;
                                this.internalPubKeys[i].State = newState;
                                return true;
                            }
                        }
                        if (this.externalPubKeys != null && this.externalPubKeys.Length > i)
                        {
                            if (this.externalPubKeys[i].P2pkScript == script
                                || this.externalPubKeys[i].P2pkhScript == script
                                || this.externalPubKeys[i].P2wpkhScript == script
                                || this.externalPubKeys[i].P2shOverP2wpkhScript == script)
                            {
                                Bip44KeyState oldState = this.externalPubKeys[i].State;
                                if (oldState == newState) return false;
                                this.externalPubKeys[i].State = newState;
                                return true;
                            }
                        }
                    }
                }
            return false;
        }

        #endregion

        #region LabelOperationsOnPubKeys

        public bool TryUpdateLabel(bool isInternal, int index, string newLabel)
        {
            if (newLabel == null) throw new ArgumentNullException(nameof(newLabel));
            if (index < 0) throw new ArgumentOutOfRangeException($"{nameof(index)} cannot be smaller than 0");
            if (isInternal)
            {
                lock (this.InternalPubKeysLock)
                {
                    if (this.internalPubKeys == null || index >= this.internalPubKeys.Length)
                    {
                        return false;
                    }

                    string oldLabel = this.internalPubKeys[index].Label;
                    if (oldLabel == newLabel) return false;
                    this.internalPubKeys[index].Label = newLabel;
                    return true;
                }
            }
            else
            {
                lock (this.ExternalPubKeysLock)
                {
                    if (this.externalPubKeys == null || index >= this.externalPubKeys.Length)
                    {
                        return false;
                    }

                    string oldLabel = this.externalPubKeys[index].Label;
                    if (oldLabel == newLabel) return false;
                    this.externalPubKeys[index].Label = newLabel;
                    return true;
                }
            }
        }
        public bool TryUpdateLabel(PubKey pubKey, string newLabel)
        {
            if (newLabel == null) throw new ArgumentNullException(nameof(newLabel));
            KeyId pubKeyHash = pubKey?.Hash;
            if (pubKeyHash == null) throw new ArgumentNullException(nameof(pubKey));

            lock (this.InternalPubKeysLock) lock (this.ExternalPubKeysLock)
                {
                    if (this.internalPubKeys == null && this.externalPubKeys == null) return false;
                    // Search by descending, newer key states will be more often modified
                    int startIterateFrom;
                    if (this.internalPubKeys == null) startIterateFrom = this.externalPubKeys.Length - 1;
                    else if (this.externalPubKeys == null) startIterateFrom = this.internalPubKeys.Length - 1;
                    else startIterateFrom = Math.Max(this.internalPubKeys.Length, this.externalPubKeys.Length) - 1;

                    for (var i = startIterateFrom; i >= 0; i--)
                    {
                        if (this.internalPubKeys != null && this.internalPubKeys.Length > i)
                        {
                            if (this.internalPubKeys[i].PubKeyHash == pubKeyHash)
                            {
                                string oldLabel = this.internalPubKeys[i].Label;
                                if (oldLabel == newLabel) return false;
                                this.internalPubKeys[i].Label = newLabel;
                                return true;
                            }
                        }
                        if (this.externalPubKeys != null && this.externalPubKeys.Length > i)
                        {
                            if (this.externalPubKeys[i].PubKeyHash == pubKeyHash)
                            {
                                string oldLabel = this.externalPubKeys[i].Label;
                                if (oldLabel == newLabel) return false;
                                this.externalPubKeys[i].Label = newLabel;
                                return true;
                            }
                        }
                    }
                }
            return false;
        }
        public bool TryUpdateLabel(BitcoinAddress address, string newLabel)
        {
            if (newLabel == null) throw new ArgumentNullException(nameof(newLabel));
            if (address == null) throw new ArgumentNullException(nameof(address));

            lock (this.InternalPubKeysLock) lock (this.ExternalPubKeysLock)
                {
                    if (this.internalPubKeys == null && this.externalPubKeys == null) return false;
                    // Search by descending, newer key states will be more often modified
                    int startIterateFrom;
                    if (this.internalPubKeys == null) startIterateFrom = this.externalPubKeys.Length - 1;
                    else if (this.externalPubKeys == null) startIterateFrom = this.internalPubKeys.Length - 1;
                    else startIterateFrom = Math.Max(this.internalPubKeys.Length, this.externalPubKeys.Length) - 1;

                    for (var i = startIterateFrom; i >= 0; i--)
                    {
                        if (this.internalPubKeys != null && this.internalPubKeys.Length > i)
                        {
                            if (this.internalPubKeys[i].P2pkhAddress == address
                                || this.internalPubKeys[i].P2wpkhAddress == address
                                || this.internalPubKeys[i].P2shOverP2wpkhAddress == address)
                            {
                                string oldLabel = this.internalPubKeys[i].Label;
                                if (oldLabel == newLabel) return false;
                                this.internalPubKeys[i].Label = newLabel;
                                return true;
                            }
                        }
                        if (this.externalPubKeys != null && this.externalPubKeys.Length > i)
                        {
                            if (this.externalPubKeys[i].P2pkhAddress == address
                                || this.externalPubKeys[i].P2wpkhAddress == address
                                || this.externalPubKeys[i].P2shOverP2wpkhAddress == address)
                            {
                                string oldLabel = this.externalPubKeys[i].Label;
                                if (oldLabel == newLabel) return false;
                                this.externalPubKeys[i].Label = newLabel;
                                return true;
                            }
                        }
                    }
                }
            return false;
        }
        public bool TryUpdateLabel(Script script, string newLabel)
        {
            if (newLabel == null) throw new ArgumentNullException(nameof(newLabel));
            if (script == null) throw new ArgumentNullException(nameof(script));

            lock (this.InternalPubKeysLock) lock (this.ExternalPubKeysLock)
                {
                    if (this.internalPubKeys == null && this.externalPubKeys == null) return false;
                    // Search by descending, newer key states will be more often modified
                    int startIterateFrom;
                    if (this.internalPubKeys == null) startIterateFrom = this.externalPubKeys.Length - 1;
                    else if (this.externalPubKeys == null) startIterateFrom = this.internalPubKeys.Length - 1;
                    else startIterateFrom = Math.Max(this.internalPubKeys.Length, this.externalPubKeys.Length) - 1;

                    for (var i = startIterateFrom; i >= 0; i--)
                    {
                        if (this.internalPubKeys != null && this.internalPubKeys.Length > i)
                        {
                            if (this.internalPubKeys[i].P2pkScript == script
                                || this.internalPubKeys[i].P2pkhScript == script
                                || this.internalPubKeys[i].P2wpkhScript == script
                                || this.internalPubKeys[i].P2shOverP2wpkhScript == script)
                            {
                                string oldLabel = this.internalPubKeys[i].Label;
                                if (oldLabel == newLabel) return false;
                                this.internalPubKeys[i].Label = newLabel;
                                return true;
                            }
                        }
                        if (this.externalPubKeys != null && this.externalPubKeys.Length > i)
                        {
                            if (this.externalPubKeys[i].P2pkScript == script
                                || this.externalPubKeys[i].P2pkhScript == script
                                || this.externalPubKeys[i].P2wpkhScript == script
                                || this.externalPubKeys[i].P2shOverP2wpkhScript == script)
                            {
                                string oldLabel = this.externalPubKeys[i].Label;
                                if (oldLabel == newLabel) return false;
                                this.externalPubKeys[i].Label = newLabel;
                                return true;
                            }
                        }
                    }
                }
            return false;
        }
        public bool TryUpdateLabels(string oldLabel, string newLabel)
        {
            if (newLabel == null) throw new ArgumentNullException(nameof(newLabel));
            if (oldLabel == null) throw new ArgumentNullException(nameof(oldLabel));
            if (oldLabel == newLabel) return false;
            var modifiedAtLeastOne = false;

            lock (this.InternalPubKeysLock)
            {
                if(this.internalPubKeys != null)
                {
                    foreach(Bip44PubKey pubKey in this.internalPubKeys)
                    {
                        if(pubKey.Label == oldLabel)
                        {
                            pubKey.Label = newLabel;
                            modifiedAtLeastOne = true;
                        }
                    }
                }
            }
            lock (this.ExternalPubKeysLock)
            {
                if (this.externalPubKeys != null)
                {
                    foreach (Bip44PubKey pubKey in this.externalPubKeys)
                    {
                        if (pubKey.Label == oldLabel)
                        {
                            pubKey.Label = newLabel;
                            modifiedAtLeastOne = true;
                        }
                    }
                }
            }

            return modifiedAtLeastOne;
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
