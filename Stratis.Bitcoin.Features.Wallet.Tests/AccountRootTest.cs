using System;
using System.Collections.Generic;
using System.Text;
using Stratis.Bitcoin.Features.Wallet;
using Xunit;
using Stratis.Bitcoin.Features.Wallet.KeyManagement;
using NBitcoin;
using System.Threading;
using System.Diagnostics;
using System.Linq;

namespace Stratis.Bitcoin.Features.Wallet.Tests
{
    public class AccountRootTest : WalletTestBase
    {
        [Fact]
        public void Foo()
        {
            Bip44KeyManager km = new Bip44KeyManager(Network.Main);
            var pw = "";
            km.InitializeNewAsync( pw, pw, Wordlist.English, WordCount.Twelve, CancellationToken.None).GetAwaiter().GetResult();

            km.CreateAccountAsync(pw, "i am label", CancellationToken.None).GetAwaiter().GetResult();
            var account = km.TryGetAccount(0);
            var label = account.Label;
            Debug.WriteLine(label);
            account.CreatePubKeys(false, "", 20);
            account.CreatePubKeys(true, "", 20);
            var pubKeys = account.GetPubKeys();
            foreach (var pk in pubKeys)
            {
                Debug.WriteLine(pk.GetP2wpkhAddress());
            }
            km.ToFileAsync("foo.wallet.txt", CancellationToken.None).GetAwaiter().GetResult();

            var km2 = new Bip44KeyManager(Network.Main);
            km2.InitializeFullyFromFileAsync("foo.wallet.txt", CancellationToken.None).GetAwaiter().GetResult();
            foreach(var pk in km2.TryGetAccount(0).GetPubKeys())
            {
                Debug.WriteLine(pk.GetP2wpkhAddress());
            }

        }
        [Fact]
        public void GetFirstUnusedAccountWithoutAccountsReturnsNull()
        {
            var accountRoot = CreateAccountRoot(CoinType.Stratis);

            var result = accountRoot.GetFirstUnusedAccount();

            Assert.Null(result);
        }

        [Fact]
        public void GetFirstUnusedAccountReturnsAccountWithLowerIndexHavingNoAddresses()
        {
            var accountRoot = CreateAccountRoot(CoinType.Stratis);
            var unused = CreateAccount("unused1");
            unused.Index = 2;
            accountRoot.Accounts.Add(unused);

            var unused2 = CreateAccount("unused2");
            unused2.Index = 1;
            accountRoot.Accounts.Add(unused2);

            var used = CreateAccount("used");
            used.ExternalAddresses.Add(CreateAddress());
            used.Index = 3;
            accountRoot.Accounts.Add(used);

            var used2 = CreateAccount("used2");
            used2.InternalAddresses.Add(CreateAddress());
            used2.Index = 4;
            accountRoot.Accounts.Add(used2);

            var result = accountRoot.GetFirstUnusedAccount();

            Assert.NotNull(result);
            Assert.Equal(1, result.Index);
            Assert.Equal("unused2", result.Name);
        }

        [Fact]
        public void GetAccountByNameWithMatchingNameReturnsAccount()
        {
            var accountRoot = CreateAccountRootWithHdAccountHavingAddresses("Test", CoinType.Stratis);            
            
            var result = accountRoot.GetAccountByName("Test");

            Assert.NotNull(result);            
            Assert.Equal("Test", result.Name);
        }

        [Fact]
        public void GetAccountByNameWithNonMatchingNameThrowsException()
        {            
            var accountRoot = CreateAccountRootWithHdAccountHavingAddresses("Test", CoinType.Stratis);

            Assert.Throws<WalletException>(() => { accountRoot.GetAccountByName("test"); });           
        }
    }
}