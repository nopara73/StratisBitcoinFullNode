using NBitcoin;
using NBitcoin.JsonConverters;
using Newtonsoft.Json;
using Stratis.Bitcoin.Features.Wallet.JsonConverters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Stratis.Bitcoin.Features.Wallet.KeyManagement
{
    [JsonObject(MemberSerialization.OptIn)]
    public class Bip44PubKey : IEquatable<Bip44PubKey>
    {
        [JsonProperty(PropertyName = "pubKey")]
        [JsonConverter(typeof(PubKeyConverter))]
        public PubKey PubKey { get; }
        [JsonProperty(PropertyName = "keyPath")]
        [JsonConverter(typeof(KeyPathJsonConverter))]
        public KeyPath Bip44KeyPath { get; }
        [JsonProperty(PropertyName = "network")]
        [JsonConverter(typeof(NetworkConverter))]
        public Network Network { get; }

        [JsonProperty(PropertyName = "label")]
        public string Label { get; set; }
        [JsonProperty(PropertyName = "state")]
        public Bip44KeyState State { get; set; }

        public Bip44PubKey(PubKey pubKey, KeyPath bip44KeyPath, Network network, string label, Bip44KeyState state)
        {
            this.PubKey = pubKey ?? throw new ArgumentNullException(nameof(pubKey));
            this.Bip44KeyPath = bip44KeyPath ?? throw new ArgumentNullException(nameof(bip44KeyPath));
            this.Network = network ?? throw new ArgumentNullException(nameof(network));
            this.Label = label ?? throw new ArgumentNullException(nameof(label));
            this.State = state;
        }

        private Script p2pkScript = null;
        public Script GetP2pkScript()
        {
            return this.p2pkScript ?? (this.p2pkScript = this.PubKey.ScriptPubKey);
        }

        private Script p2pkhScript = null;
        public Script GetP2pkhScript()
        {
            return this.p2pkhScript ?? (this.p2pkhScript = this.PubKey.Hash.ScriptPubKey);
        }

        private Script p2wpkhScript = null;
        public Script GetP2wpkhScript()
        {
            return this.p2wpkhScript ?? (this.p2wpkhScript = this.PubKey.WitHash.ScriptPubKey);
        }

        private Script p2shOverP2wpkhScript = null;
        public Script GetP2shOverP2wpkhScript()
        {
            return this.p2shOverP2wpkhScript ?? (this.p2shOverP2wpkhScript = GetP2wpkhScript().Hash.ScriptPubKey);
        }

        private BitcoinPubKeyAddress p2pkhAddress = null;
        public BitcoinPubKeyAddress GetP2pkhAddress()
        {
            return this.p2pkhAddress ?? (this.p2pkhAddress = this.PubKey.GetAddress(this.Network));
        }

        private BitcoinWitPubKeyAddress p2wpkhAddress = null;
        public BitcoinWitPubKeyAddress GetP2wpkhAddress()
        {
            return this.p2wpkhAddress ?? (this.p2wpkhAddress = this.PubKey.GetSegwitAddress(this.Network));
        }

        private BitcoinScriptAddress p2shOverP2wpkhAddress = null;
        public BitcoinScriptAddress GetP2shOverP2wpkhAddress()
        {
            return this.p2shOverP2wpkhAddress ?? (this.p2shOverP2wpkhAddress = GetP2wpkhScript().GetScriptAddress(this.Network));
        }

        private int? index = null;
        public int GetIndex()
        {
            return (int)(this.index ?? (this.index = (int)this.Bip44KeyPath.Indexes[4]));
        }

        private bool? isInternal = null;
        public bool IsInternal()
        {
            if (this.isInternal == null)
            {
                int change = (int)this.Bip44KeyPath.Indexes[3];
                if (change == 0)
                {
                    this.isInternal = false;
                }
                else if (change == 1)
                {
                    this.isInternal = true;
                }
                else throw new ArgumentException(nameof(this.Bip44KeyPath));
            }
            return (bool)this.isInternal;
        }

        #region Equality
        
        // speedup
        private KeyId pubKeyHash = null;
        public KeyId GetPubKeyHash()
        {
            return this.pubKeyHash ?? (this.pubKeyHash = this.PubKey.Hash);
        }

        public override bool Equals(object obj) => obj is Bip44PubKey && this == (Bip44PubKey)obj;
        public bool Equals(Bip44PubKey other) => this == other;
        // speedup
        private int? hashCode = null;
        public override int GetHashCode()
        {
            return (int)(this.hashCode ?? (this.hashCode = this.PubKey.Hash.GetHashCode()));
        }
        public static bool operator ==(Bip44PubKey x, Bip44PubKey y)
        {
            return x.GetPubKeyHash() == y.GetPubKeyHash();
        }
        public static bool operator !=(Bip44PubKey x, Bip44PubKey y)
        {
            return !(x == y);
        }

        #endregion
    }
}
