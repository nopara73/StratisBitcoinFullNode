using NBitcoin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Stratis.Bitcoin.Features.Wallet.KeyManagement
{
    public class HdPubKey
    {
        public Network Network { get; }
        public PubKey PubKey { get; }

        public Script P2pkhScriptPubKey { get; }
        public Script P2wpkhScriptPubKey { get; }
        public Script P2shOverP2wpkhScriptPubKey { get; }

        public BitcoinPubKeyAddress P2pkhAddress { get; }
        public BitcoinWitPubKeyAddress P2wpkhAddress { get; }
        public BitcoinScriptAddress P2shOverP2wpkhAddress { get; }

        public KeyPath Path { get; }

        public HdKeyState State { get; set; }
        public string Label { get; set; }

        public int Index { get; }
        public bool IsInternal { get; }

        public HdPubKey(Network network, PubKey pubKey, KeyPath path, string label = "")
        {
            this.Network = network ?? throw new ArgumentNullException(nameof(network));
            this.PubKey = pubKey ?? throw new ArgumentNullException(nameof(pubKey));
            this.Path = path ?? throw new ArgumentNullException(nameof(path));
            this.Label = label ?? throw new ArgumentNullException(nameof(label));

            this.P2pkhScriptPubKey = pubKey.Hash.ScriptPubKey;
            this.P2wpkhScriptPubKey = pubKey.WitHash.ScriptPubKey;
            this.P2shOverP2wpkhScriptPubKey = this.P2wpkhScriptPubKey.Hash.ScriptPubKey;

            this.P2pkhAddress = pubKey.GetAddress(network);
            this.P2wpkhAddress = pubKey.GetSegwitAddress(network);
            this.P2shOverP2wpkhAddress = this.P2wpkhScriptPubKey.GetScriptAddress(network);

            this.State = HdKeyState.Clean;
            this.Label = label;

            var indexes = path.Indexes.Skip(path.Indexes.Count() - 2).ToArray();
            if (indexes[0] == 0)
            {
                this.IsInternal = false;
            }
            else if (indexes[0] == 1)
            {
                this.IsInternal = true;
            }
            else throw new ArgumentException(nameof(path));

            this.Index = (int)indexes[1];
        }
    }
}
