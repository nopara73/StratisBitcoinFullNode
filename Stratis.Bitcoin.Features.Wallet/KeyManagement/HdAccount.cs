using NBitcoin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Stratis.Bitcoin.Features.Wallet.KeyManagement
{
    public class HdAccount : IEquatable<HdAccount>
    {
        public int Index { get; }

        public KeyPath Path { get; }
        public KeyPath InternalChainPath { get; }
        public KeyPath ExternalChainPath { get; }

        public ExtPubKey ExtPubKey { get; }
        public ExtPubKey InternalChainExtPubKey { get; }
        public ExtPubKey ExternalChainExtPubKey { get; }

        /// <summary>
        /// Label by pubkey, not by scriptPubKey/Address for privacy
        /// When tx is spend, the pubkey is exposed
        /// </summary>
        public string Label { get; set; }

        public HdAccount(ExtPubKey extPubKey, KeyPath path, string label = "")
        {
            this.Label = label ?? throw new ArgumentNullException(nameof(label));

            this.ExtPubKey = extPubKey ?? throw new ArgumentNullException(nameof(extPubKey));
            this.ExternalChainExtPubKey = extPubKey.Derive(0, false);
            this.InternalChainExtPubKey = extPubKey.Derive(1, false);

            this.Path = path ?? throw new ArgumentNullException(nameof(path));
            this.ExternalChainPath = path.Derive(0, false);
            this.InternalChainPath = path.Derive(1, false);
            this.Index = (int)(path.Indexes.Last() - 2147483648);
        }

        #region Equality

        public override bool Equals(object obj) => obj is HdAccount && this == (HdAccount)obj;
        public bool Equals(HdAccount other) => this == other;
        public override int GetHashCode()
        {
            var hash = this.ExtPubKey.ToHex().GetHashCode();
            hash = hash ^ this.Path.ToString().GetHashCode();
            return hash;
        }
        public static bool operator ==(HdAccount x, HdAccount y)
        {
            return x.ExtPubKey.ToHex() == y.ExtPubKey.ToHex() && x.Path.ToString() == y.Path.ToString();
        }

        public static bool operator !=(HdAccount x, HdAccount y)
        {
            return !(x == y);
        }

        #endregion
    }
}
