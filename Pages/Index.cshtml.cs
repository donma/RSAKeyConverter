using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;

namespace RSAKeyConverter.Pages
{
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;

        public string PubKey { get; set; }

        public string PrivateKey { get; set; }
        public IndexModel(ILogger<IndexModel> logger)
        {
            _logger = logger;
        }

        public void OnGet()
        {
            
            var  rsa = System.Security.Cryptography.RSA.Create();
           
            PubKey = rsa.ToXmlString(false);

            PrivateKey = rsa.ToXmlString(true);

        }
    }
}
