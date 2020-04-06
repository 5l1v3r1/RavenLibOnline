using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace RavenLibOnline
{
    public class Networking
    {
        public static WebClient generalWebClient = new WebClient();
        public static string downloadString(string address)
        {
            try
            {
                return generalWebClient.DownloadString(address);
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex);
                throw new Exception();
            }
        }
        public static void downloadFile(string address, string outputFileName)
        {
            try
            {
                generalWebClient.DownloadFile(address, outputFileName);
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex);
                throw new Exception();
            }
        }
        public static byte[] downloadData(string address)
        {
            try
            {
                return generalWebClient.DownloadData(address);
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex);
                throw new Exception();
            }
        }
        public static void setGeneralProxy(IWebProxy webProxy)
        {
            try
            {
                generalWebClient.Proxy = webProxy;
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex);
                throw new Exception();
            }
        }
        public static void setGeneralEncoding(Encoding encoding)
        {
            try
            {
                generalWebClient.Encoding = encoding;
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex);
                throw new Exception();
            }
        }
        public static bool checkOnlineStatus()
        {
            try
            {
                string google = generalWebClient.DownloadString("https://google.de");
                return true;
            }
            catch (Exception ex)
            {

                Debug.WriteLine(ex);
                return false;
            }
        }

    }
}
