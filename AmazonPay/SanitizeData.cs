using System;
using System.Collections.Generic;
using System.Xml;
using System.Configuration;
using System.Web;
using Newtonsoft.Json.Linq;

namespace AmazonPay
{
    /// <summary>
    /// Static Class for Sanitizing data for request and Response
    /// </summary>
    public static class SanitizeData
    {
        /// <summary>
        /// Enum datatype for Sanitazation
        /// </summary>
        public enum DataType
        {
            Request,
            Response,
            Text,
            JsonString
        };

        /// <summary>
        ///  Function for sanitizing data
        /// </summary>
        /// <param name="data">String XML data</param>
        /// <param name="type">Type of Data beeing provided</param>
        /// <returns>Sanitized String of data</returns>
        public static string SanitizeGivenData(string data, DataType type)
        {
            string returnString = string.Empty;
            const string REMOVED_TEXT = "*REMOVED*";
            List<string> sanitizeList = new List<string>();

            if (string.IsNullOrEmpty(ConfigurationManager.AppSettings["sanitizeList"]))
                throw new ArgumentException("You have set Logger but we are missing sanitezeList property in configuration file. \n " +
                                    "Please add:'  \n" +
                                    "<appSettings> \n" +
                                    "<add key=\"sanitizeList\" value=\"Example1;Example2;Example3\"/> \n" +
                                    "</appSettings>");

            // Load list of sanitized tags in to array
            string[] listArray = ConfigurationManager.AppSettings["sanitizeList"].Split(new char[] { ';', ' ' }, StringSplitOptions.RemoveEmptyEntries);
            // Load SanitizeDataList
            foreach (var item in listArray)
            {
                sanitizeList.Add(item);
            }
            // return data if sanitazation list is empty
            if (sanitizeList.Count < 1) return data;

            // Response Data type
            if (type == DataType.Response)
            {
                // Load data as XML
                XmlDocument doc = new XmlDocument();

                doc.LoadXml(data);

                // Find and remove data
                foreach (string item in sanitizeList)
                {
                    XmlNode node = doc.GetElementsByTagName(item).Item(0);
                    if (node != null && node.ChildNodes.Count > 0)
                    {
                        node.InnerText = REMOVED_TEXT;
                    }
                }
                returnString = doc.OuterXml;

            }
            // Request Data type
            else if (type == DataType.Request)
            {
                string[] separatedURLQueryString = data.Split('\n');

                var queryString = HttpUtility.ParseQueryString(separatedURLQueryString[separatedURLQueryString.Length - 1].TrimStart());

                // Load SanitizeDataList
                foreach (var item in sanitizeList)
                {
                    // Remove unwanted queries
                    if (!String.IsNullOrEmpty(queryString[item])) queryString.Set(item, REMOVED_TEXT);
                }

                separatedURLQueryString[separatedURLQueryString.Length - 1] = queryString.ToString();

                Array.ForEach(separatedURLQueryString, value => returnString += value + '\n');

                returnString = returnString.Remove(returnString.Length - 1);
            }
            // Json Data type
            else if (type == DataType.JsonString)
            {
                var jsonObj = JObject.Parse(data);

                // Load SanitizeDataList
                foreach (var item in sanitizeList)
                {
                    // Replace unwanted data
                    if (jsonObj[item] != null)
                        jsonObj[item].Replace(REMOVED_TEXT);
                }

                returnString = Newtonsoft.Json.JsonConvert.SerializeObject(jsonObj, Newtonsoft.Json.Formatting.Indented);
            }
            // Text Data Type
            else if (type == DataType.Text)
            {
                foreach (var item in sanitizeList)
                {
                    string maskedValue = "@#" + item + "#@";
                    int startIndex = data.IndexOf(maskedValue);
                    if (startIndex > 0)
                    {
                        int endIndex = data.LastIndexOf(maskedValue) + (maskedValue.Length);
                        int length = endIndex - startIndex;
                        string value = data.Substring(startIndex, length);
                        data = data.Replace(value, REMOVED_TEXT);
                    }
                }
                System.Text.RegularExpressions.Regex objRegEx = new System.Text.RegularExpressions.Regex("@#[^#@]*#@", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                returnString = objRegEx.Replace(data, ""); 
            }
            return returnString;
        }
    }
}
