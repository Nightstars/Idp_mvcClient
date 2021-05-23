using IdentityModel.Client;
using Idp_mvcClient.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace Idp_mvcClient.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public async Task<IActionResult> Index()
        {
            var client = new HttpClient();
            var disco = await client.GetDiscoveryDocumentAsync("https://localhost:5001");
            if (disco.IsError)
                throw new Exception(disco.Error);
            var accessToken = await HttpContext.GetTokenAsync(OpenIdConnectParameterNames.AccessToken);
            client.SetBearerToken(accessToken);
            var response = await client.GetAsync("https://localhost:5003/identity");
            if (!response.IsSuccessStatusCode)
            {
                if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                {
                    accessToken = await RenewTokensAsync();
                    return RedirectToAction();
                }
                throw new Exception(response.ReasonPhrase);
            }
                
            var content = await response.Content.ReadAsStringAsync();
            return View("Index", content);
        }

        public async Task<IActionResult> Privacy()
        {
            var accessToken = await HttpContext.GetTokenAsync(OpenIdConnectParameterNames.AccessToken);
            var idToken = await HttpContext.GetTokenAsync(OpenIdConnectParameterNames.IdToken);
            var refreshToken = await HttpContext.GetTokenAsync(OpenIdConnectParameterNames.RefreshToken);
            var authorizationCode = await HttpContext.GetTokenAsync(OpenIdConnectParameterNames.Code);
            List<string> data = new List<string>();
            data.Add($"accessToken,{accessToken}");
            data.Add($"idToken,{idToken}");
            data.Add($"refreshToken,{refreshToken}");
            ViewBag.data = data;
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        #region Logout
        /// <summary>
        /// Logout
        /// </summary>
        /// <returns></returns>
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            await HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);
            return View("Index");
        }
        #endregion

        #region RenewTokensAsync
        public async Task<string> RenewTokensAsync()
        {
            var client = new HttpClient();
            var disco = await client.GetDiscoveryDocumentAsync("https://localhost:5001");
            if (disco.IsError)
                throw new Exception(disco.Error);
            var refreshToken = await HttpContext.GetTokenAsync(OpenIdConnectParameterNames.RefreshToken);
            //refresh access token
            var tokenResponse =await client.RequestRefreshTokenAsync(new RefreshTokenRequest { 
                Address=disco.TokenEndpoint,
                ClientId= "mvc client",
                ClientSecret= "mvc client",
                Scope= "scope1 openid profile email phone address",
                GrantType=OpenIdConnectGrantTypes.RefreshToken,
                RefreshToken=refreshToken,
            });
            if (tokenResponse.IsError)
                throw new Exception(tokenResponse.Error);
            else
            {
                var expiresAt = DateTime.UtcNow + TimeSpan.FromSeconds(tokenResponse.ExpiresIn);
                var tokens = new[] {
                    new AuthenticationToken
                    {
                        Name=OpenIdConnectParameterNames.IdToken,
                        Value=tokenResponse.IdentityToken
                    },
                    new AuthenticationToken
                    {
                        Name=OpenIdConnectParameterNames.AccessToken,
                        Value=tokenResponse.AccessToken
                    },
                    new AuthenticationToken
                    {
                        Name=OpenIdConnectParameterNames.RefreshToken,
                        Value=tokenResponse.RefreshToken
                    },
                    new AuthenticationToken
                    {
                        Name="expires_at",
                        Value=expiresAt.ToString("o",CultureInfo.InvariantCulture)
                    }
                };
                //获取身份认证结果，包含当前Principal和Properties
                var currentAuthenticationResult = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                //把新的tokens存起来
                currentAuthenticationResult.Properties.StoreTokens(tokens);
                //再登录
                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                    currentAuthenticationResult.Principal, currentAuthenticationResult.Properties);
            }
            return tokenResponse.AccessToken;
        }
        #endregion
    }
}
