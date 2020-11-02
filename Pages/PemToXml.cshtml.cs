using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace RSAKeyConverter.Pages
{
    public class PemToXmlModel : PageModel
    {

        public string PEMData { get; set; }

        public string XMLData { get; set; }

        public string ErrorJS { get; set; }
        public void OnGet()
        {
        }

        public IActionResult OnPostConvertXML(string pemdata)
        {
            PEMData = pemdata;

            RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
            try
            {
                if (pemdata.Contains("PUBLIC KEY-----"))
                {
                    var ber = PemToBer(pemdata, "PUBLIC KEY");
                    provider.ImportSubjectPublicKeyInfo(ber, out _);

                    XMLData = provider.ToXmlString(false);
                }

                else if (pemdata.Contains("PRIVATE KEY-----"))
                {
                    var ber = PemToBer(pemdata, "PRIVATE KEY");
                    provider.ImportPkcs8PrivateKey(ber, out _);

                    XMLData = provider.ToXmlString(true);
                }
                else
                {
                    ErrorJS = "<script>toastr.error('Must be contain PRIVATE KEY----- or PUBLIC KEY-----');</script>";
                }
            }
            catch (Exception ex)
            {
                ErrorJS = "<script>toastr.error('" + ex.Message.Replace("'", "¡¦") + "')</script>";
            }

            return Page();
        }

        private static byte[] PemToBer(string pem, string header)
        {
            // Technically these should include a newline at the end,
            // and either newline-or-beginning-of-data at the beginning.
            string begin = $"-----BEGIN {header}-----";
            string end = $"-----END {header}-----";

            int beginIdx = pem.IndexOf(begin);
            int base64Start = beginIdx + begin.Length;
            int endIdx = pem.IndexOf(end, base64Start);

            return Convert.FromBase64String(pem.Substring(base64Start, endIdx - base64Start));
        }

    }
}
