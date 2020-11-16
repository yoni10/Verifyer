
using DecoderTool;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using SignerTool;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;


namespace Verifyer
{
    public class Program
    {
        static void Main(string[] args)
        {
            Test();
        }

        public static void Test()
        {
            string publicKey = File.ReadAllText(@"files\publicKey.pem");
            string privateKey = File.ReadAllText(@"files\privateKey.pem");

            var claims = new List<Claim>();
            claims.Add(new Claim("claim1", "value1"));
            claims.Add(new Claim("claim2", "value2"));
            claims.Add(new Claim("claim3", "value3"));

            var token = CreateToken1(privateKey);
            token = CreateToken(claims, privateKey);
            token = Signer.Sign(claims);
            String payload = DecodeToken(token, publicKey);
            payload = Decoder.Decode(token, publicKey);
            ValidateTokenParams(payload);
        }

        public static string ValidateTokenParams(String payload)
        {
            Dictionary<String, String>  res = JsonConvert.DeserializeObject<Dictionary<String, String>>(payload);
            
            String claim1;
            res.TryGetValue("claim1", out claim1);
            Newtonsoft.Json.Linq.JObject jObject = Newtonsoft.Json.Linq.JObject.Parse(payload);
            String f = (String)jObject["claim1"];

            return null;
        }

        public static string CreateToken(List<Claim> claims, string privateRsaKey)
        {
            RSAParameters rsaParams;
            using (var tr = new StringReader(privateRsaKey))
            {
                var pemReader = new PemReader(tr);
                RsaPrivateCrtKeyParameters keyPair = (RsaPrivateCrtKeyParameters)pemReader.ReadObject();
                if (keyPair == null)
                {
                    throw new Exception("Could not read RSA private key");
                }
                //var privateRsaParams = keyPair.Private as RsaPrivateCrtKeyParameters;
                rsaParams = DotNetUtilities.ToRSAParameters(keyPair);
            }
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(rsaParams);
                Dictionary<string, object> payload = claims.ToDictionary(k => k.Type, v => (object)v.Value);
                return Jose.JWT.Encode(payload, rsa, Jose.JwsAlgorithm.PS256);
            }
        }

        public static string DecodeToken(string token, string publicRsaKey)
        {
            RSAParameters rsaParams;

            using (var tr = new StringReader(publicRsaKey))
            {
                var pemReader = new PemReader(tr);
                var publicKeyParams = pemReader.ReadObject() as RsaKeyParameters;
                if (publicKeyParams == null)
                {
                    throw new Exception("Could not read RSA public key");
                }
                rsaParams = DotNetUtilities.ToRSAParameters(publicKeyParams);
            }
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(rsaParams);
                // This will throw if the signature is invalid
                return Jose.JWT.Decode(token, rsa, Jose.JwsAlgorithm.PS256);
            }
        }

        public static string CreateToken1(string privateRsaKey)
        {
            string jwt = string.Empty;
            RsaPrivateCrtKeyParameters keyPair;

            Dictionary<string, object> payload = new Dictionary<string, object>();
            payload.Add("my", "claim");
            //var cert = ConfigurationManager.AppSettings["cert"];
            /// cert begins -----BEGIN PRIVATE KEY----- and ends with -END PRIVATE KEY-----";

            using (var sr = new StringReader(privateRsaKey))
            {
                PemReader pr = new PemReader(sr);
                keyPair = (RsaPrivateCrtKeyParameters)pr.ReadObject();
            }

            RSAParameters rsaParams = DotNetUtilities.ToRSAParameters(keyPair);

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(rsaParams);

                jwt = Jose.JWT.Encode(payload, rsa, Jose.JwsAlgorithm.PS256);
            }

            return jwt;
        }
    }
}
