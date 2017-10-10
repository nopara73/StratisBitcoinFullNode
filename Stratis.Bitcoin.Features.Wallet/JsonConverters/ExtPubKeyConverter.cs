using NBitcoin;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Text;

namespace Stratis.Bitcoin.Features.Wallet.JsonConverters
{
    public class ExtPubKeyConverter : JsonConverter
    {
        /// <inheritdoc />
        public override bool CanConvert(Type objectType)
        {
            return objectType == typeof(BitcoinEncryptedSecretNoEC);
        }

        /// <inheritdoc />
        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {            
            return ExtPubKey.Parse((string)reader.Value);
        }

        /// <inheritdoc />
        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            // Network doesn't matter, it'll be serialized in a network independent way
            writer.WriteValue(((ExtPubKey)value).GetWif(Network.Main).ToString());
        }
    }
}
