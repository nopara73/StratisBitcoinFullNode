using NBitcoin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Stratis.Bitcoin.Features.Wallet.KeyManagement
{
    public class Bip44PubKey : IEquatable<Bip44PubKey>
    {
        public PubKey PubKey { get; }
        public KeyPath Bip44KeyPath { get; }
        public Network Network { get; }

        public string Label { get; set; }
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
        public Script P2pkScript
        {
            get
            {
                return this.p2pkScript ?? (this.p2pkScript = this.PubKey.ScriptPubKey);
            }
        }

        private Script p2pkhScript = null;
        public Script P2pkhScript
        {
            get
            {
                return this.p2pkhScript ?? (this.p2pkhScript = this.PubKey.Hash.ScriptPubKey);
            }
        }

        private Script p2wpkhScript = null;
        public Script P2wpkhScript
        {
            get
            {
                return this.p2wpkhScript ?? (this.p2wpkhScript = this.PubKey.WitHash.ScriptPubKey);
            }
        }

        private Script p2shOverP2wpkhScript = null;
        public Script P2shOverP2wpkhScript
        {
            get
            {
                return this.p2shOverP2wpkhScript ?? (this.p2shOverP2wpkhScript = this.P2wpkhScript.Hash.ScriptPubKey);
            }
        }

        private BitcoinPubKeyAddress p2pkhAddress = null;
        public BitcoinPubKeyAddress P2pkhAddress
        {
            get
            {
                return this.p2pkhAddress ?? (this.p2pkhAddress = this.PubKey.GetAddress(this.Network));
            }
        }

        private BitcoinWitPubKeyAddress p2wpkhAddress = null;
        public BitcoinWitPubKeyAddress P2wpkhAddress
        {
            get
            {
                return this.p2wpkhAddress ?? (this.p2wpkhAddress = this.PubKey.GetSegwitAddress(this.Network);
            }
        }

        private BitcoinScriptAddress p2shOverP2wpkhAddress = null;
        public BitcoinScriptAddress P2shOverP2wpkhAddress
        {
            get
            {
                return this.p2shOverP2wpkhAddress ?? (this.p2shOverP2wpkhAddress = this.P2wpkhScript.GetScriptAddress(this.Network));
            }
        }

        private int? index = null;
        public int Index
        {
            get
            {
                return (int)(this.index ?? (this.index = (int)this.Bip44KeyPath.Indexes[4]));
            }
        }

        private bool? isInternal = null;
        public bool IsInternal
        {
            get
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
        }

        #region Equality

        // speedup
        private int? hashCode = null;
        private int HashCode
        {
            get
            {
                return (int)(this.hashCode ?? (this.hashCode = this.PubKey.Hash.GetHashCode()));
            }
        }

        // speedup
        private KeyId pubKeyHash = null;
        public KeyId PubKeyHash
        {
            get
            {
                return this.pubKeyHash ?? (this.pubKeyHash = this.PubKey.Hash);
            }
        }

        public override bool Equals(object obj) => obj is Bip44PubKey && this == (Bip44PubKey)obj;
        public bool Equals(Bip44PubKey other) => this == other;
        public override int GetHashCode()
        {
            return this.HashCode;
        }
        public static bool operator ==(Bip44PubKey x, Bip44PubKey y)
        {
            return x.PubKeyHash == y.PubKeyHash;
        }
        public static bool operator !=(Bip44PubKey x, Bip44PubKey y)
        {
            return !(x == y);
        }

        #endregion
    }
}
