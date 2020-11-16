using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SignerTool
{
    public class Signer
    {
        public static string Sign(List<Claim> claims)
        {
            String privateRsaKey = "-----BEGIN PRIVATE KEY-----" + Environment.NewLine +
                                    "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC7UjVL9QdmNOes" + Environment.NewLine +
                                    "vcLOHTe2uvnrrgKpjIGEvFyTypowiTaLy8kxKkD6K6n6PtVEGfV0cZXYknXkSflE" + Environment.NewLine +
                                    "JidR7SZ9UgfcivIAbt2LmHQjg0jQW+0eBqfr/XvSErssRdt5uiQh1HrxxctK/Vsk" + Environment.NewLine +
                                    "M6d3r6u/RCE5dFoqU6y+S2EcWikvFbqSdjo3TMb4V3mjOFa5/hWi+6OdJP8oMRa8" + Environment.NewLine +
                                    "nFKNaZH5TiBMOfmJQYy4UdDTTWUg/0lA7n4a+zGzjoWRUVerc1oLAzvyr7MmsT4/" + Environment.NewLine +
                                    "yixWhws789Yv4oIqML4Jay6c3+Q3OdJtAAEe8cauVQPtjOddRURvOWotXH8iAbNk" + Environment.NewLine +
                                    "XUxErAmZAgMBAAECggEAU6nxAf7rkhu5Ce8rTdHA641xSHFM4RtPUdCrbJsF6P2v" + Environment.NewLine +
                                    "7hpTvvDHWrUb0xgzOpp5hcuhiLxJiW/8tBJyZ2YLVdfIiRlJ4yWhL9MktCPT5rPY" + Environment.NewLine +
                                    "IRwJ7h4mKnqRPMHqt+CKeM2lJ80W8mRcS7wCZTOB+whb6oRsLRF4Svnx4q7mTA+b" + Environment.NewLine +
                                    "pTlNhhbT5fPr+tfndHNu0vcH/ExK0uqJsccydNcF9lr+1rTRMXSwuqyFssDYlRI2" + Environment.NewLine +
                                    "SDn6PxZc7QsgdouTzM08pCL3xuER6vHDWsn64TaWXRtTcCvLz0LIfhbdCo7PzJTD" + Environment.NewLine +
                                    "9P96UJKvhnu4n+N41fa8bSwmwsYvz62PGDYwBw3krQKBgQD96q97RsaDshcKhwrT" + Environment.NewLine +
                                    "DvKCQ2jE9+UlYGSmXdtkhmt1ohJ4uThUfwkLZLqReTku1cy8VhXJzc9WubrTuk9B" + Environment.NewLine +
                                    "nuhTI+5FzFyuh9dA2W3HwW06Ynglknk1sn/mx9Giy+V6IULYlFKbZnA7oEBVtyU5" + Environment.NewLine +
                                    "tCbg9uHYNYdXDHNOMWTPEQilvwKBgQC826YDJ2AazytvkSDfu5EvCZF2SXxGV0np" + Environment.NewLine +
                                    "EaaucdGu+HIfQVK4PBT13KUbPOFpyAUoB7JicspornRlOGSWc84ak9wWhPtnYOzF" + Environment.NewLine +
                                    "+Pb80eOjkPBhkMNEe2lNSF/tY+I2JAXtOmrP+UTjyfu+wR0LKuJ+VpG7EMa6wx1S" + Environment.NewLine +
                                    "dW/MR5aWpwKBgE9l7FuDBR43OQc8tQDMYr6i74bv8UJfwvlWzfzAH6gX9uizGk8p" + Environment.NewLine +
                                    "rh1W8RP+MQhZKH0X+hYxeg0nZKlCT/g4BXPB/4bp4W1d4sxPcQmOjWY9Vk6BX8+P" + Environment.NewLine +
                                    "snjqsL3UPjyTXAC3WKFpRd0PPi7PZx+FGscry/E8w8ZPiVrBDUHGlMqnAoGARaOg" + Environment.NewLine +
                                    "1azhTUFzPNKBEr7xTCz1DG8QekeZo220zsJ9lU1bl5bYz8Kn3/kakK6kWAM/k4Ez" + Environment.NewLine +
                                    "EAZQCMW7ec+Pl8LgDwDSuSMUKQyegmnJeXRTwm6hlPhyaIAxViQH61tXgKtL3Cwc" + Environment.NewLine +
                                    "UtARzQUf5TkEYqfPmNKHLjmDbj6gQ1W2gdcr+iUCgYAilbyZ6pvGzNZql5Pfx7uH" + Environment.NewLine +
                                    "RQZIn8x6+iY8qhHi1Hd8QnvggsTYRBsHt2iKsZrqNwVKQWf/tIlR5y5TAX4p0mFT" + Environment.NewLine +
                                    "iQvHAtYwUMOu+aH91W65VHX08bdWcpJ+6cM5pBsKJgEfFpYrFQNkGYAH8z6/gUm4" + Environment.NewLine +
                                    "EcouQ/+w2t41ceKNbRz3GA==" + Environment.NewLine +
                                    "-----END PRIVATE KEY-----";

            RSAParameters rsaParams;
            using (var tr = new StringReader(privateRsaKey))
            {
                var pemReader = new PemReader(tr);
                RsaPrivateCrtKeyParameters keyPair = (RsaPrivateCrtKeyParameters)pemReader.ReadObject();
                if (keyPair == null)
                {
                    throw new Exception("Could not read RSA private key");
                }
                
                rsaParams = DotNetUtilities.ToRSAParameters(keyPair);
            }
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(rsaParams);
                Dictionary<string, object> payload = claims.ToDictionary(k => k.Type, v => (object)v.Value);
                return Jose.JWT.Encode(payload, rsa, Jose.JwsAlgorithm.PS256);
            }
        }

    }
}
