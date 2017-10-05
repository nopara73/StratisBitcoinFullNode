using System;
using System.Collections.Generic;
using System.Text;

namespace Stratis.Bitcoin.Features.Wallet.KeyManagement
{
    /// <summary>
	/// Purpose defined by BIP33 https://github.com/bitcoin/bips/blob/master/bip-0043.mediawiki
	/// </summary>
	public enum HdPurpose
    {
        Bip44,
        Bip49
    }
}
