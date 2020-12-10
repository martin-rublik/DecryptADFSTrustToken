using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using CommandLine;

namespace DecryptADFSTrustToken
{
    class Program
    {
        class Options
        {
            [Option('i', "infile", Required = true,
            HelpText = "Input file with encrypted ADFS token.")]
            public string InFile { get; set; }

            [Option('o', "outfile", Required = false,
            HelpText = "Output file - decrypted token.")]
            public string OutFile { get; set; }

            [Option('k', "p12file", Required = true, SetName = "PfxDecryption",
            HelpText = "PFX/PKCS12 file to use for decryption.")]
            public string P12FilePath { get; set; }

            [Option('p', "p12password", Required = true, SetName = "PfxDecryption",
            HelpText = "PKCS12 password.")]
            public string P12Password { get; set; }
        }


        // Thanks to:
        //  https://gist.githubusercontent.com/yaronn/6765830/raw/6227439f25c34208355dbe1e347d77962606675e/decrypt
        //  the IV is the first 16 byes(in our case) of the encrypted cipher(not key)
        private static byte[] GetIV(byte[] cypher)
        {
            byte[] IV = new byte[16];
            Array.Copy(cypher, IV, 16);
            return IV;
        }

        internal static byte[] ExtractIVAndDecrypt(SymmetricAlgorithm algorithm, byte[] cipherText, int offset, int count)
        {
            byte[] buffer2;
            if (cipherText == null)
            {
                throw new Exception();
            }
            if ((count < 0) || (count > cipherText.Length))
            {
                throw new Exception();
            }
            if ((offset < 0) || (offset > (cipherText.Length - count)))
            {
                throw new Exception();
            }
            int num = algorithm.BlockSize / 8;
            byte[] dst = new byte[num];
            Buffer.BlockCopy(cipherText, offset, dst, 0, dst.Length);
            //algorithm.Padding = PaddingMode.ISO10126;
            algorithm.Mode = CipherMode.CBC;
            try
            {
                using (ICryptoTransform transform = algorithm.CreateDecryptor(algorithm.Key, dst))
                {
                    buffer2 = transform.TransformFinalBlock(cipherText, offset + dst.Length, count - dst.Length);
                }
            }
            catch (CryptographicException exception)
            {
                throw exception;
            }
            return buffer2;
        }

        static void RunParsed(Options options)
        {
            // load the xml document
            XmlDocument xmlDoc = new XmlDocument();
            try
            {
                xmlDoc.PreserveWhitespace = true;
                xmlDoc.Load(options.InFile);
            
            }catch(Exception e)
            {
                throw new Exception(
                    String.Format("Unable to load xml document from {0}.", options.InFile),
                    e
                );
            }

            // add namespaces necessery for lookup
            var namespaceManager = new XmlNamespaceManager(xmlDoc.NameTable);
            namespaceManager.AddNamespace("xenc", "http://www.w3.org/2001/04/xmlenc#");
            namespaceManager.AddNamespace("xdsig", "http://www.w3.org/2000/09/xmldsig#");

            // search for encrypted session key and encrypted data
            XmlElement encryptedSessionKeyXML = xmlDoc.SelectSingleNode("/xenc:EncryptedData/xdsig:KeyInfo/xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue", namespaceManager) as XmlElement;
            if (encryptedSessionKeyXML==null)
            {
                throw new Exception("Unable to locate encrypted session key, ADFS token format might be different. Searching for /xenc:EncryptedData/xdsig:KeyInfo/xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue");
            }

            XmlElement encryptedDataXML = xmlDoc.SelectSingleNode("/xenc:EncryptedData/xenc:CipherData/xenc:CipherValue", namespaceManager) as XmlElement;
            if (encryptedDataXML == null)
            {
                throw new Exception("Unable to locate encrypted data, ADFS token format might be different. Searching for /xenc:EncryptedData/xenc:CipherData/xenc:CipherValue");
            }

            // decrypt session key
            byte[] key;
            try
            {
                X509Certificate2 P12Container = new X509Certificate2(File.ReadAllBytes(options.P12FilePath), options.P12Password);
                RSACryptoServiceProvider rsa = (RSACryptoServiceProvider)P12Container.PrivateKey;
                key = rsa.Decrypt(Convert.FromBase64String(encryptedSessionKeyXML.InnerText), true);
            }
            catch(Exception e)
            {
                throw new Exception(
                    String.Format("Unable to decrypt session key using {0}, reasons might include bad file path, incorrect p12 password or incorrectly encrypted data.", options.P12FilePath),
                    e
                );
            }


            // get encrypted data bytes
            byte[] encryptedBytes;
            try
            {
                encryptedBytes = Convert.FromBase64String(encryptedDataXML.InnerText);
            }catch(Exception e)
            {
                throw new Exception("Unable to b64 decode encrypted data.", e );
            }

            // get the IV
            byte[] iv = GetIV(encryptedBytes);

            string body;
            try
            {
                // decrypt the data
                var AesManagedAlg = new AesCryptoServiceProvider();
                AesManagedAlg.KeySize = 256;
                AesManagedAlg.Key = key;
                AesManagedAlg.IV = iv;

                body = UTF8Encoding.UTF8.GetString(ExtractIVAndDecrypt(AesManagedAlg, encryptedBytes, 0, encryptedBytes.Length));
            }catch(Exception e)
            {
                throw new Exception("Unable to decrypt encrypted data.", e);
            }

            // format the token
            string formattedXml;
            try
            {
                XmlDocument token = new XmlDocument();
                token.LoadXml(body);

                MemoryStream mStream = new MemoryStream();
                XmlTextWriter writer = new XmlTextWriter(mStream, Encoding.UTF8);

                writer.Formatting = Formatting.Indented;

                // Write the XML into a formatting XmlTextWriter
                token.WriteContentTo(writer);
                writer.Flush();
                mStream.Flush();

                // Have to rewind the MemoryStream in order to read
                // its contents.
                mStream.Position = 0;

                // Read MemoryStream contents into a StreamReader.
                StreamReader sReader = new StreamReader(mStream);

                // Extract the text from the StreamReader.
                formattedXml = sReader.ReadToEnd();

                // Output
                Debug.WriteLine(formattedXml);
            }catch(Exception e)
            {
                throw new Exception("Unable to format decrypted data as XML.", e);
            }

            if (string.IsNullOrEmpty(options.OutFile))
            {
                Console.WriteLine(formattedXml);
            }else
            {
                System.IO.File.WriteAllText(options.OutFile, formattedXml);
            }
        }

        static int Main(string[] args)
        {
            try
            {
                var parserResult = Parser.Default.ParseArguments<Options>(args)
                    .WithParsed(options => RunParsed(options));
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("ERROR: {0}", e.Message);
                Console.Error.WriteLine("Exception type: {0}", e.GetType().ToString());
                Console.Error.WriteLine("StackTrace: {0}", e.StackTrace);
                if (!(e.InnerException == null))
                {
                    Console.Error.WriteLine("Inner Exception: {0}", e.InnerException.Message);
                }
                return -1;
            }
            return 0;
        }
    }
}
