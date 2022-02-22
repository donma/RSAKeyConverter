using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace RSAKeyConverter.Pages
{
    public class XmlToPemModel : PageModel
    {

        public string PEMData { get; set; }

        public string XMLData { get; set; }

        public string ErrorJS { get; set; }
        public void OnGet()
        {
            //https://stackoverflow.com/questions/53997902/how-to-get-rsacryptoserviceprovider-public-and-private-key-only-in-c-sharp
        }

        public IActionResult OnPostConvertPEM(string xmldata)
        {
            XMLData = xmldata;

            RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
            try
            {
                provider.FromXmlString(xmldata);

                byte[] ber = null;
                if (provider.PublicOnly)
                {
                    ber = provider.ExportSubjectPublicKeyInfo();
                    PEMData = MakePem(ber, "PUBLIC KEY");
                }
                else
                {
                    ber = provider.ExportRSAPrivateKey();
                    PEMData = MakePem(ber, "RSA PRIVATE KEY");
                }
            }
            catch(Exception ex) {
                ErrorJS = "<script>toastr.error('"+ex.Message.Replace("'","¡¦")+"')</script>";
            }

            return Page();
        }


        private static string MakePem(byte[] ber, string header = "PUBLIC KEY")
        {
            var builder = new StringBuilder("-----BEGIN ");
            builder.Append(header);
            builder.AppendLine("-----");

            string base64 = Convert.ToBase64String(ber);
            int offset = 0;
            const int LineLength = 64;

            while (offset < base64.Length)
            {
                int lineEnd = Math.Min(offset + LineLength, base64.Length);
                builder.AppendLine(base64.Substring(offset, lineEnd - offset));
                offset = lineEnd;
            }

            builder.Append("-----END ");
            builder.Append(header);
            builder.AppendLine("-----");
            return builder.ToString();
        }




    }
}
