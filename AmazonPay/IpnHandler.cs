using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Text;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Net;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using AmazonPay;
using System.Xml;
using AmazonPay.Responses;
using System.Text.RegularExpressions;
using Common.Logging;

namespace AmazonPay
{
    /// <summary>
    /// Notification types received
    /// </summary>
    public enum NotificationType
    {
        OrderReferenceNotification, BillingAgreementNotification, PaymentAuthorize, PaymentCapture, PaymentRefund, ProviderCredit, ProviderCreditReversal, ChargebackDetailedNotification
    }

    /// <summary>
    /// Class IPN_Handler
    /// Takes headers and body of the IPN message as input in the constructor
    /// verifies that the IPN is from the right resource and has the valid data
    /// </summary>
    public class IpnHandler
    {
        private JObject parsedMessage;
        private X509Certificate2 x509Cert;

        private string notificationReferenceId;
        private string notificationType;
        private string sellerId;
        private string marketplaceId;
        private string releaseEnvironment;
        private string notificationData;
        private string timeStamp;
        private string version;

        private OrderReferenceDetailsResponse orderReferenceDetailsObject;
        private AuthorizeResponse authorizeResponseObject;
        private CaptureResponse captureResponseObject;
        private RefundResponse refundResponseObject;
        private GetProviderCreditDetailsResponse providerCreditResponseObject;
        private GetProviderCreditReversalDetailsResponse providerCreditReversalResponseObject;
        private BillingAgreementDetailsResponse billingAgreementDetailsObject;
        private ChargebackResponse chargebackResponseObject;

        /// <summary>
        ///  Common Logger Property
        /// </summary>
        public ILog Logger { private get; set; }

        /// <summary>
        /// IpnHandler takes Ipn Headers and JSON data
        /// </summary>
        /// <param name="headers"></param>
        /// <param name="jsonMessage"></param>
        public IpnHandler(NameValueCollection headers, string jsonMessage)
        {
            IpnHandlerInit(headers, jsonMessage);
        }

        /// <summary>
        /// IpnHandler takes Ipn Header, JSON data and Logger Object
        /// </summary>
        /// <param name="headers"></param>
        /// <param name="jsonMessage"></param>
        /// <param name="logger"></param>
        public IpnHandler(NameValueCollection headers, string jsonMessage, ILog logger)
        {
            this.Logger = logger;
            IpnHandlerInit(headers, jsonMessage);
        }

        /// <summary>
        /// IpnHandler Initializer
        /// </summary>
        private void IpnHandlerInit(NameValueCollection headers, string jsonMessage)
        {
            try
            {
                if (!string.IsNullOrEmpty(jsonMessage))
                {
                    headers = LowerHeadersKeysCase(headers);
                    ParseRawMessage(headers, jsonMessage);
                    GetIpnResponseObjects();
                }
            }
            catch (HttpParseException ex)
            {
                throw new HttpParseException("Error Parsing the IPN notification", ex);
            }

        }

        /// <summary>
        /// Converting the key to lowercase in NameValueCollection headers as headers key can be uppercase in the request
        /// </summary>
        /// <param name="headers"></param>
        /// <returns>Lower cased keys in NameValueCollection headers</returns>
        private static NameValueCollection LowerHeadersKeysCase(NameValueCollection headers)
        {
            NameValueCollection lowerKeyHeaders = new NameValueCollection();
            foreach (string key in headers.AllKeys)
            {
                lowerKeyHeaders.Add(key.ToLower(), headers[key]);
            }
            return lowerKeyHeaders;
        }

        /// <summary>
        /// Convert a raw http POST request that contains an IPN and
        /// convert to an object
        ///
        /// Will throw a Exception if the content is not a valid IPN
        ///
        /// Callers are expected to return a 503 http code an exception is
        /// thrown by this method, otherwise reply with a HTTP OK status
        /// </summary>
        /// <param name="headers"></param>
        /// <param name="body"></param>
        private void ParseRawMessage(NameValueCollection headers, string body)
        {
            ParseNotification(headers, body);
            ValidateMessageIsTrusted();
        }

        /// <summary>
        /// Parse a json string in an sns format and convert it into a message object that stores key/value pairs
        /// </summary>
        /// <param name="headers"></param>
        /// <param name="snsJson"></param>
        private void ParseNotification(NameValueCollection headers, string snsJson)
        {
            ValidateHeader(headers);
            parseMessage(snsJson);
            ValidateCertUrl();
            ValidateMessageType();
            LogRequestDetails(headers, this.ToXml());
        }

        private void LogRequestDetails(NameValueCollection headers, string message)
        {
            // Build string for Logging headers
            StringBuilder sb = new StringBuilder();

            for (int i = 0; i < headers.Count; i++)
            {
                string key = headers.GetKey(i);
                sb.AppendLine("[Key: " + key + ", Value: @#" + key +"#@" + headers.GetValues(headers.GetKey(i))[0] + "@#" + key +"#@]");
            }
            // Logging headers
            LogMessage(sb.ToString(), AmazonPay.SanitizeData.DataType.Text);
            // Logging response
            LogMessage(message, SanitizeData.DataType.Response);
        }

        /// <summary>
        /// Check the sns headers to ensure that the notification is valid
        /// </summary>
        /// <param name="headers"></param>
        private static void ValidateHeader(NameValueCollection headers)
        {
            string messageType = null;

            try
            {
                messageType = headers["x-amz-sns-message-type"];
            }
            catch (NullReferenceException nre)
            {
                throw new NullReferenceException("Expected headers to be passed, null value received", nre);
            }

            if (messageType == null)
            {
                throw new NullReferenceException("Error with message - header does not contain x-amz-sns-message-type");
            }

            if (!messageType.Equals("Notification", StringComparison.InvariantCultureIgnoreCase))
            {
                throw new NullReferenceException(String.Format("Error with sns message - header x-amz-sns-message-type is invalid", messageType));
            }
        }

        /// <summary>
        /// Ensure that the sns message is the valid notificaton type
        /// </summary>
        private void ValidateMessageType()
        {
            string notificatonType = GetMandatoryField("Type");
            if (!notificatonType.Equals("Notification", StringComparison.InvariantCultureIgnoreCase))
            {
                throw new Exception("METHOD__ValidateMessageType |" + String.Format("Error with sns notification - unexpected message with Type of ", notificatonType));
            }
        }

        /// <summary>
        /// Create a new message the acts as a wrapper around the json string
        /// </summary>
        /// <param name="json"></param>
        private void parseMessage(string json)
        {
            try
            {
                this.parsedMessage = JObject.Parse(json);
            }
            catch (Exception ex)
            {
                throw new Exception("Error with message - content is not in json format", ex);
            }
        }

        /// <summary>
        /// Return the value associated with the field name, throws an exception if it cannot be found
        /// </summary>
        /// <param name="fieldName"></param>
        /// <returns>string value for the fieldname</returns>
        private string GetMandatoryField(string fieldName)
        {
            JToken value = GetValueAsToken(fieldName);
            return value.ToString();
        }

        /// <summary>
        /// Return the value of the field as a timestamp
        /// </summary>
        /// <param name="fieldName"></param>
        /// <returns>DateTime representation of the object</returns>
        private DateTime GetMandatoryFieldAsDateTime(string fieldName)
        {
            try
            {
                return (DateTime)GetValueAsToken(fieldName);
            }
            catch (FormatException fe)
            {
                throw new FormatException(String.Format("Error with message - expected field should be of type DateTime object", fieldName), fe);
            }
        }

        /// <summary>
        /// Return the JToken associated with this field, otherwise throw an exception
        /// </summary>
        /// <param name="fieldName"></param>
        /// <returns>JToken value</returns>
        private JToken GetValueAsToken(string fieldName)
        {
            JToken value = this.parsedMessage.GetValue(fieldName);

            if (value == null)
            {
                throw new NullReferenceException(String.Format("Error with message - mandatory field cannot be found", fieldName));
            }
            return value;
        }

        /// <summary>
        /// Get the value associated with this field, or return null if not present
        /// </summary>
        /// <param name="fieldName"></param>
        /// <returns>String or null if not defined</returns>
        private String GetField(string fieldName)
        {
            JToken value = this.parsedMessage.GetValue(fieldName);
            if (value != null)
            {
                return value.ToString();
            }
            else
            {
                return null;
            }
        }

        /// <summary>
        /// Verifies that the signing certificate url is from a recognizable source.
        /// Returns the cert url if it cen be verified, otherwise throws an exception.
        /// </summary>
        /// <param name="signingCertURL"></param>
        /// <returns></returns>
        private void ValidateCertUrl()
        {
            bool isValidUrl = false;
            string signingCertURL = GetMandatoryField("SigningCertURL");
            var uri = new Uri(signingCertURL);

            if (uri.Scheme == "https" && signingCertURL.EndsWith(".pem", StringComparison.Ordinal))
            {
                const string pattern = @"^sns\.[a-zA-Z0-9\-]{3,}\.amazonaws\.com(\.cn)?$";
                var regex = new Regex(pattern);
                if (!regex.IsMatch(uri.Host))
                {
                    isValidUrl = false;
                }
                else
                {
                    isValidUrl = true;
                }
            }
            if (!isValidUrl)
            {
                throw new InvalidDataException("Signing certificate url is not from a recognised source.");
            }
        }

        /// <summary>
        /// Validates if the Signature version is correct , else throws an exception
        /// </summary>
        private void ValidateMessageIsTrusted()
        {
            string signatureVersion = GetMandatoryField("SignatureVersion");

            switch (signatureVersion)
            {
                case "1":
                    VerifySnsMessageWithVersion1SignatureAlgorithm();
                    break;
                default:
                    throw new InvalidDataException(String.Format("Error with sns message verification - message is signed with unknown signature specification", signatureVersion));
            }
        }

        /// <summary>
        /// Invoke the version 1 signature algorithm and throw an exception if it fails
        /// </summary>
        private void VerifySnsMessageWithVersion1SignatureAlgorithm()
        {
            bool isValid = VerifyMsgMatchesSignatureV1WithCert();
            if (!isValid)
            {
                throw new InvalidDataException(String.Format("Error with sns message - signature verification failed", "1"));
            }
        }

        /// <summary>
        /// Perform the comparison of the message data with the signature,
        /// as described on http://docs.aws.amazon.com/sns/latest/dg/SendMessageToHttp.verify.signature.html,
        /// for version 1 of the signature algorithm
        /// </summary>
        /// <returns>true if verified, otherwise false</returns>
        private bool VerifyMsgMatchesSignatureV1WithCert()
        {
            if (!GetMandatoryField("Type").Equals("Notification"))
            {
                throw new InvalidDataException("Error with sns message verification - message is not of type Notification, no implementation of signing algorithm is present for other notification types");
            }

            string certPath = GetMandatoryField("SigningCertURL");
            x509Cert = GetCertificate(certPath);

            if (!VerifyCertIsIssuedByAmazon())
            {
                throw new InvalidDataException("Error with sns message verification - certificate in Notification is not a valid certificate issued to Amazon");
            }

            UTF8Encoding encoding = new UTF8Encoding();
            string msg = GetMessageToSign();
            byte[] data = encoding.GetBytes(msg);

            // Server signature uses base 64 encoding, must desconstruct
            byte[] decodedSignature = Convert.FromBase64String(GetMandatoryField("Signature"));

            return VerifyMsgMatchesSignatureWithPublicCert(data, decodedSignature);
        }

        /// <summary>
        /// Extract the contents of the message and build a string to hash in order to verify the signature
        /// Expected string is a single string in format field name\n field value\n, with the field names in alphabetical byte order (e.g. A-Za-z)
        /// notification use the Message, MessageId, Subject if provided, Timestamp, TopicArn & Type fields
        /// </summary>
        /// <returns>StringBuilder builder</returns>
        private string GetMessageToSign()
        {
            StringBuilder builder = new StringBuilder();

            builder.Append("Message\n");
            builder.Append(GetMandatoryField("Message"));
            builder.Append("\n");
            builder.Append("MessageId\n");
            builder.Append(GetMandatoryField("MessageId"));
            builder.Append("\n");
            String subject = GetField("Subject");
            if (subject != null)
            {
                builder.Append("Subject\n");
                builder.Append(subject);
                builder.Append("\n");
            }
            builder.Append("Timestamp\n");
            builder.Append(GetMandatoryFieldAsDateTime("Timestamp")
                .ToString(Constants.Iso8601UTCDateWithMillisecondsFormatString, System.Globalization.CultureInfo.InvariantCulture));
            builder.Append("\n");
            builder.Append("TopicArn\n");
            builder.Append(GetMandatoryField("TopicArn"));
            builder.Append("\n");
            builder.Append("Type\n");
            builder.Append(GetMandatoryField("Type"));
            builder.Append("\n");

            return builder.ToString();
        }

        /// <summary>
        /// Verify that certificate is valid and issued by Amazon.
        /// </summary>
        /// <returns></returns>
        private bool VerifyCertIsIssuedByAmazon()
        {
            return VerifyCertificateChain() && VerifyCertificateSubject(GetSubject());
        }

        /// <summary>
        /// Verify the certificate subject, checks the "CN" attribute
        /// </summary>
        /// <param name="subject"></param>
        /// <returns>value of the attribute or false</returns>
        private bool VerifyCertificateSubject(String subject)
        {
            string[] subjectAttributeDelimiters = new string[] { ", " };
            string[] subjectAttributesArr = subject.Split(subjectAttributeDelimiters, StringSplitOptions.None);
            List<string> subjectAttributesList = convertSubjectAttributesArr(subjectAttributesArr);

            Dictionary<string, string> subjectAttributes = new Dictionary<string, string>();
            char[] keyValueDelimiter = { '=' };
            foreach (string subjectAttribute in subjectAttributesList)
            {

                string[] keyValuePair = subjectAttribute.Split(keyValueDelimiter, 2);
                string key = keyValuePair[0];
                string value = keyValuePair[1];

                if (subjectAttributes.ContainsKey(key))
                {
                    // indicates certificate tampering, as we have an invalid subject with duplicate key types
                    return false;
                }
                else
                {
                    subjectAttributes.Add(key, value);
                }
            }
            return ContainsAttribute(subjectAttributes, "CN", Constants.CertCN);
        }

        private List<string> convertSubjectAttributesArr(string[] subjectAttributesArr)
        {
            // Because ', ' is the delimiter, the value "Amazon.com, Inc." will get delimited when splitting the string.
            // This algorithm will merge the two delimited strings "Amazon.com" and "Inc." back into "Amazon.com, Inc.".
            List<string> subjectAttributes = new List<string>();
            for (int i = 0; i < subjectAttributesArr.Length; i++)
            {
                string subjectAttribute = subjectAttributesArr[i];
                if (!subjectAttribute.Contains("="))
                {
                    subjectAttributes[i - 1] = subjectAttributes[i - 1] + ", " + subjectAttribute;
                }
                else
                {
                    subjectAttributes.Add(subjectAttribute);
                }
            }

            return subjectAttributes;
        }

        private bool ContainsAttribute(Dictionary<string, string> subjectAttributes, string attributeKey, string attributeValue)
        {
            string actualValue;
            if (!subjectAttributes.TryGetValue(attributeKey, out actualValue))
            {
                return false;
            }

            return actualValue == attributeValue;
        }

        /// <summary>
        /// Perform the comparison of the message data with the signature
        /// </summary>
        /// <param name="data"></param>
        /// <param name="signature"></param>
        /// <returns>true if successful</returns>
        private bool VerifyMsgMatchesSignatureWithPublicCert(byte[] data, byte[] signature)
        {
            RSACryptoServiceProvider csp = (RSACryptoServiceProvider)GetPublicKey();
            return csp.VerifyData(data, CryptoConfig.MapNameToOID("SHA1"), signature);
        }

        /// <summary>
        ///  Check the application cache for the certificate, and use this if still valid
        ///  If not found, request the cert and add to the cache with a timeout of 24 hours
        /// </summary>
        /// <param name="certPath"></param>
        /// <returns>Instance of the x508 certificate</returns>
        private X509Certificate2 GetCertificate(string certPath)
        {
            X509Certificate2 cert = null;
            try
            {
                cert = (X509Certificate2)HttpRuntime.Cache.Get(String.Format(Constants.CacheKey, certPath));
            }
            catch (HttpException ex)
            {
                throw new HttpException("Error requesting certificate", ex);
            }

            if (cert == null)
            {
                cert = GetCertificateFromURI(certPath);
                HttpRuntime.Cache.Insert(String.Format(Constants.CacheKey, certPath), cert, null, DateTime.UtcNow.AddDays(1.0), System.Web.Caching.Cache.NoSlidingExpiration);
            }

            return cert;
        }

        /// <summary>
        /// Request the certifcate from the given URI
        /// </summary>
        /// <param name="certPath"></param>
        /// <returns>Instance of the x508 certificate</returns>
        private X509Certificate2 GetCertificateFromURI(string certPath)
        {
            WebClient wc = new WebClient();
            byte[] raw = wc.DownloadData(certPath);
            return new X509Certificate2(raw);
        }

        /// <summary>
        /// Performs certificate chain validation using basic validation policy
        /// </summary>
        /// <returns>x509Cert.Verify() result</returns>
        private bool VerifyCertificateChain()
        {
            return x509Cert.Verify();
        }

        /// <summary>
        /// Gets certificate's subject information
        /// </summary>
        /// <returns>x509Cert.Subject</returns>
        private String GetSubject()
        {
            return x509Cert.Subject;
        }

        /// <summary>
        /// Gets AsymmetricAlgorithm representing the certificate's public key
        /// </summary>
        /// <returns>x509Cert.PublicKey.Key value</returns>
        private AsymmetricAlgorithm GetPublicKey()
        {
            return x509Cert.PublicKey.Key;
        }


        /// <summary>
        /// Parse the Notification into API Response objects.
        /// </summary>
        private void GetIpnResponseObjects()
        {
            string xml;
            xml = this.ToXml();

            if (Enum.IsDefined(typeof(NotificationType), this.GetNotificationType()))
            {
                switch ((NotificationType)Enum.Parse(typeof(NotificationType), this.GetNotificationType()))
                {
                    case NotificationType.OrderReferenceNotification:
                        orderReferenceDetailsObject = new OrderReferenceDetailsResponse(xml);
                        break;
                    case NotificationType.BillingAgreementNotification:
                        billingAgreementDetailsObject = new BillingAgreementDetailsResponse(xml);
                        break;
                    case NotificationType.PaymentAuthorize:
                        authorizeResponseObject = new AuthorizeResponse(xml);
                        break;
                    case NotificationType.PaymentCapture:
                        captureResponseObject = new CaptureResponse(xml);
                        break;
                    case NotificationType.PaymentRefund:
                        refundResponseObject = new RefundResponse(xml);
                        break;
                    case NotificationType.ProviderCredit:
                        providerCreditResponseObject = new GetProviderCreditDetailsResponse(xml);
                        break;
                    case NotificationType.ProviderCreditReversal:
                        providerCreditReversalResponseObject = new GetProviderCreditReversalDetailsResponse(xml);
                        break;
                    case NotificationType.ChargebackDetailedNotification:
                        chargebackResponseObject = new ChargebackResponse(xml);
                        break;
                }
            }
        }

        /// <summary>
        /// Convert IPN message to JSON type
        /// </summary>
        /// <returns>IPN in JSON string format </returns>
        public string ToJson()
        {
            string xmlResponse;
            string json;

            xmlResponse = this.ToXml();
            var xml = new XmlDocument();
            xml.LoadXml(xmlResponse);
            json = JsonConvert.SerializeObject(xml, Newtonsoft.Json.Formatting.Indented);
            return json;
        }

        /// <summary>
        /// Convert IPN message to XML type
        /// </summary>
        /// <returns>IPN in XML string format</returns>
        public string ToXml()
        {
            JObject message = JObject.Parse(this.parsedMessage.GetValue("Message").ToString());
            string xmlResponse = message.GetValue("NotificationData").ToString().Trim();
            parseRemainingIpnFields();
            return xmlResponse;
        }

        /// <summary>
        /// Convert IPN message to Dictionary type
        /// </summary>
        /// <returns>IPN in Dictionary(string,object) format</returns>
        public Dictionary<string, object> ToDict()
        {
            string json = ToJson();
            Dictionary<string, object> dict = JsonConvert.DeserializeObject<Dictionary<string, object>>(
                json, new JsonConverter[] { new AmazonPay.JsonParser() });
            return dict;
        }

        /// <summary>
        /// parseRemainingIpnFields() - Parses the remaining fields of the IPN
        /// </summary>
        private void parseRemainingIpnFields()
        {
            JObject message = JObject.Parse(this.parsedMessage.GetValue("Message").ToString());
            this.notificationReferenceId = message.GetValue("NotificationReferenceId").ToString();
            this.notificationType = message.GetValue("NotificationType").ToString();
            this.sellerId = message.GetValue("SellerId").ToString();
            this.releaseEnvironment = message.GetValue("ReleaseEnvironment").ToString();
            this.timeStamp = message.GetValue("Timestamp").ToString();
            this.marketplaceId = message.GetValue("MarketplaceID").ToString();
            this.version = message.GetValue("Version").ToString();
        }


        /// <summary>
        /// Getter for the sellerId from the IPN Message
        /// </summary>
        /// <returns>sellerId</returns>
        public string GetSellerId()
        {
            return this.sellerId;
        }

        /// <summary>
        /// Getter for the timeStamp in the IPN Message
        /// </summary>
        /// <returns>timeStamp</returns>
        public string GetTimeStamp()
        {
            return this.timeStamp;
        }

        /// <summary>
        /// Getter for the marketplaceId in the IPN Message
        /// </summary>
        /// <returns>marketplaceId</returns>
        public string GetMarketplaceId()
        {
            return this.marketplaceId;
        }

        /// <summary>
        /// Getter for the version in the IPN Message
        /// </summary>
        /// <returns>version</returns>
        public string GetVersion()
        {
            return this.version;
        }


        /// <summary>
        /// Getter for the NotificationReferenceId in the IPN Message
        /// </summary>
        /// <returns>notificationReferenceId</returns>
        public string GetNotificationReferenceId()
        {
            return this.notificationReferenceId;
        }

        /// <summary>
        /// Getter for the type of ReleaseEnvironment in the IPN Message
        /// </summary>
        /// <returns>releaseEnvironment</returns>
        public string GetReleaseEnvironment()
        {
            return this.releaseEnvironment;
        }

        /// <summary>
        /// Getter for the type of notification received
        /// The return type is a string and not an Enum for forward compatibility.
        /// </summary>
        /// <returns>notificationType</returns>
        public string GetNotificationType()
        {
            return this.notificationType.Replace(" ","");
        }

        /// <summary>
        /// Getter for the OrderReferenceDetailsResponse object for OrderReferenceDetails IPN
        /// </summary>
        /// <returns>OrderReferenceDetailsResponse Object</returns>
        public OrderReferenceDetailsResponse GetOrderReferenceDetailsResponse()
        {
            return this.orderReferenceDetailsObject;
        }

        /// <summary>
        /// Getter for the BillingAgreementDetailsResponse object for BillingAgreementDetails IPN
        /// </summary>
        /// <returns>BillingAgreementDetailsResponse Object</returns>
        public BillingAgreementDetailsResponse GetBillingAgreementDetailsResponse()
        {
            return this.billingAgreementDetailsObject;
        }

        /// <summary>
        /// Getter for the AuthorizeResponse object for Authorize IPN
        /// </summary>
        /// <returns>AuthorizeResponse Object</returns>
        public AuthorizeResponse GetAuthorizeResponse()
        {
            return this.authorizeResponseObject;
        }

        /// <summary>
        /// Getter for the CaptureResponse object for Capture IPN
        /// </summary>
        /// <returns>CaptureResponse Object</returns>
        public CaptureResponse GetCaptureResponse()
        {
            return this.captureResponseObject;
        }

        /// <summary>
        /// Getter for the RefundResponse object for Refund IPN
        /// </summary>
        /// <returns>RefundResponse Object</returns>
        public RefundResponse GetRefundResponse()
        {
            return this.refundResponseObject;
        }

        /// <summary>
        /// Getter for the ProviderCreditDetailsResponse object for ProviderCredit IPN
        /// </summary>
        /// <returns>GetProviderCreditDetailsResponse Object</returns>
        public GetProviderCreditDetailsResponse GetProviderCreditDetailsResponse()
        {
            return this.providerCreditResponseObject;
        }

        /// <summary>
        /// Getter for the ProviderCreditReversalDetailsResponse object for ProviderCreditReversal IPN
        /// </summary>
        /// <returns>GetProviderCreditReversalDetailsResponse Object</returns>
        public GetProviderCreditReversalDetailsResponse GetProviderCreditReversalDetailsResponse()
        {
            return this.providerCreditReversalResponseObject;
        }

        /// <summary>
        /// Getter for the ChargebackResponse object for ChargebackDetailed IPN
        /// </summary>
        /// <returns>ChargebackIpnResponse Object</returns>
        public ChargebackResponse GetChargebackResponse()
        {
            return this.chargebackResponseObject;
        }

        /// <summary>
        /// Helper method to log data within Client
        /// </summary>
        /// <param name="message"></param>
        /// <param name="type"></param>
        private void LogMessage(string message, SanitizeData.DataType type)
        {
            if (this.Logger != null && this.Logger.IsDebugEnabled)
            {
                this.Logger.Debug(SanitizeData.SanitizeGivenData(message, type));
            }
        }
    }
}