using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using VirusTotalNET;
using VirusTotalNET.Objects;
using System.IO;

namespace DLVT
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void iTalk_Button_22_Click(object sender, EventArgs e)
        {
            // initializing VT with API key
            VirusTotal VT = new VirusTotal("c9836f1fb3196ec1205c4eb4f58cc50be1b41915f2b18633927e8a7333457cc8");

            // Yes we want to use HTTPS instead of HTTP
            VT.UseTLS = true;

            // Getting our file 
            FileInfo fileInfo = new FileInfo("asdf.txt"/*iTalk_TextBox_Small2.Text*/);

            //debug purpose 
            File.WriteAllText(fileInfo.FullName, @"purpletestfislekkkk");

            // Getting our fileReport
            FileReport fileReport = VT.GetFileReport(fileInfo);

            // Checking weather or not there is a previous scan on the file
            bool prevScan = fileReport.ResponseCode == ReportResponseCode.Present;
            
            // If there was a previous scan or if prevScan = true ( its a bool )
            // Update our label to let the users know there is a pervious scan
            // else
            // We want to upload the file and get the scan report
            // ( this is where PrintScan(ScanResult scanresult) comes into play ) 
            if (prevScan)
            {
                PrintScan(fileReport);
                iTalk_Label7.Text = "YES";
                iTalk_Label7.ForeColor = Color.Green;
            }
            else
            {
                ScanResult fileReport2 = VT.ScanFile(fileInfo);
                PrintScan(fileReport2);
                iTalk_Label7.Text = "NO";
                iTalk_Label7.ForeColor = Color.Red;
            }
            
        }

        // Goto VT Button
        // Takes the user to the virustotal site of their scanned file
        private void iTalk_Button_24_Click(object sender, EventArgs e)
        {
            // Checking to make sure ScanID isn't empty
            if (!String.IsNullOrEmpty(iTalk_TextBox_Small3.Text))
            {
                string VTScanID = iTalk_TextBox_Small3.Text;
                //Removing the past 11 chars or so 
                // E.g ScanID 1e5408577b802de6aaed8240f3c4c2b8b0b3fee9d1fcafef84bdb8c716181b88-1435728995
                // We don't need the -######### so lets just remove everything from it
                string VTscanUrl = VTScanID.Remove(64);
                System.Diagnostics.Process.Start("https://www.virustotal.com/en/file/" + VTscanUrl + "/analysis/");
            }
            else
            {
                MessageBox.Show("You must first scan the file!");
            }
        }

        // if there isn't an active scan report already on the file
        // we want to go a head and grab the ScanID from it
        // and apply it to our Scan URL textbox.
        // this way we can either A: re-scan and get the updated
        // detections list or click VT Button and visit the site
        // directly.
        private void PrintScan(ScanResult scanResult)
        {
             iTalk_TextBox_Small3.Text = scanResult.ScanId;
        }

        // Grabs the report and allows us to access some information
        // We add +1 for each detection to our label
        // and add each detection to the llistbox
        // with the AV name that detected a positive trigger.
        private void PrintScan(FileReport fileReport)
        {
            int detectedCount = 0;

            if (fileReport.ResponseCode == ReportResponseCode.Present)
            {
                // foreach loop for each scan results in fileReport
                foreach (ScanEngine scan in fileReport.Scans)
                {
                    // Checking weather or not there is a detection
                    // If so we want to add the information to our listbox
                    bool scangoodbad = scan.Detected;

                    // for debugging purposes we are just checking for 'good' detections or detections = false
                    if (scangoodbad == false) 
                    {
                        detectedCount = Convert.ToInt32(iTalk_Label8.Text);
                        detectedCount += 1; // for each detection we want to add +1 to our label
                        iTalk_Label8.Text = detectedCount.ToString();
                        listBox1.Items.Add(string.Format("AV: {0} | Detected: {1}", scan.Name, scan.Detected));
                        string scanID = fileReport.ScanId;
                        iTalk_TextBox_Small3.Text = scanID;
                        
                    }

                }

            }
        }
    }
}
