/*
THIS TRIGGER IS TO GET UPDATE FROM DETECTION, AND TURN THOSE DETECTION TYPE TO CUSTOM METRICS
SO USERS CAN BUILD CUSTOM DASHBOARD FROM DETECTION THAT HAS HAPPENED
THIS TRIGGER USES 'DETECTION_UPDATE' EVENT TO CHECK THE DETECTION.

you can choose not to send these to recordstore by setting const EXA_RECORDS to False

and replace variable DiscoverURI with your EDA (ExtraHop Discover Appliance) IP Address 
*/

/*
LIST DETECTION TYPE:
====================
new_external_rdp_connection
dns_zone_transfer
tcp_null_fin_or_xmas_scan
tcp_syn_scan
rdp_brute_force
custom.Suspicious_Network_packets
suspicious_http_port
unknown_public_dns_server
potential_covert_channel
external_db_req
eternalblue_exploit
interactive_traffic_shell
external_db_req
interactive_traffic_shell
ftp_brute_force
rare_ssh_port
domain_generation_algorithm
anonymous_ftp
ti_dns_host
ti_http_host
sqli_attack
msrpc_scheduled_task_via_ITaskSchedulerService
custom.PUBLICLY_EXPOSED_DATABASE_SERVER
custom.PUBLICLY_EXPOSED_FTP_SERVER
llmnr_poisoning
custom.PUBLICLY_EXPOSED_STORAGE_SERVER
custom.PUBLICLY_EXPOSED_RDP_SERVER
data_exfiltration
interactive_traffic_ssh
ping_scan
new_external_ssh_connection
new_telnet_activity
new_external_telnet_connection
ntlmv1_authentication
ti_tcp_incoming
web_directory_scan
new_local_dns_server
psexec_activity
c2_web_beaconing
wmi_activity
blacklisted_cert
wsman_activity
unconventional_data_transfer
ti_http_uri
ti_tcp_outgoing
dns_internal_reverse_lookup_scan
database_brute_force
smb_cifs_valid_login_errors
new_external_rdp_connection
unconventional_ssh_data_trasnfer
suspicious_tld
unconventional_rdp_data_trasnfer
expired_cert
weak_cipher
inbound_tor_connection
smb_cifs_share_enumeration
database_transaction_failures
http_internal_error
cryptocurrency_mining
*/

var app = Application("MDetection");
var tipe = Detection.type;
var updateTime = convertTimestamp(Detection.updateTime);
var startTime = convertTimestamp(Detection.startTime);
var endTime = convertTimestamp(Detection.endTime);
var title = Detection.title;
var riskScore = ""+ Detection.riskScore;
var deskripsi = Detection.description;


switch (tipe){
/*
case "cryptocurrency_mining":
  addMetric();
break;
*/
case "cryptocurrency_mining":
  addMetric();
break;
case "http_internal_error":
  addMetric();
break;
case "database_transaction_failures":
  addMetric();
break;
case "smb_cifs_share_enumeration":
  addMetric();
break;
case "inbound_tor_connection":
  addMetric();
break;
case "weak_cipher":
  addMetric();
break;
case "expired_cert":
  addMetric();
break;
case "unconventional_rdp_data_trasnfer":
  addMetric();
break;
case "suspicious_tld":
  addMetric();
break;
case "unconventional_ssh_data_trasnfer":
  addMetric();
break;
case "new_external_rdp_connection":
  addMetric();
break;
case "smb_cifs_valid_login_errors":
  addMetric();
break;
case "database_brute_force":
  addMetric();
break;
case "dns_internal_reverse_lookup_scan":
  addMetric();
break;
case "ti_tcp_outgoing":
  addMetric();
break;
case "ti_http_uri":
  addMetric();
break;
case "unconventional_data_transfer":
  addMetric();
break;
case "c2_web_beaconing":
  addMetric();
  AFTP_c2WB();
break;
case "wsman_activity":
  addMetric();
break;
case "blacklisted_cert":
  addMetric();
break;
case "wmi_activity":
  addMetric();
break;
case "ti_tcp_incoming":
  addMetric();
break;
case "psexec_activity":
  addMetric();
break;
case "new_local_dns_server":
  addMetric();
break;
case "web_directory_scan":
  addMetric();
break;
case "ti_tcp_incoming":
  addMetric();
break;
case "ntlmv1_authentication":
  addMetric();
break;
case "new_external_telnet_connection":
  addMetric();
  tampil();
break;
case "new_telnet_activity":
  addMetric();
break;
case "new_external_ssh_connection":
  addMetric();
break;
case "ping_scan":
  addMetric();
break;
case "interactive_traffic_ssh":
  addMetric();
break;
case "data_exfiltration":
  addMetric();
break;
case "custom.PUBLICLY_EXPOSED_DATABASE_SERVER":
  addMetric();
  ExpDBSvr();
break;
case "custom.PUBLICLY_EXPOSED_RDP_SERVER":
  addMetric();
  ExpFTPStr();
break;
case "custom.PUBLICLY_EXPOSED_STORAGE_SERVER":
  addMetric();
  StrgClnt()
break;
case "llmnr_poisoning":
  addMetric();
break;
case "custom.PUBLICLY_EXPOSED_FTP_SERVER":
  addMetric();
  ExpFTPStr();
break;
case "msrpc_scheduled_task_via_ITaskSchedulerService":
  addMetric();
break;
case "sqli_attack":
  addMetric();
break;
case "ti_dns_host":
  addMetric();
break;
case "ti_http_host":
  addMetric();
break;
case "ti_dns_host":
  addMetric();
break;
case "anonymous_ftp":
  addMetric();
  AFTP_c2WB();
break;
case "domain_generation_algorithm":
  addMetric();
break;
case "rare_ssh_port":
  addMetric();
break;
case "ftp_brute_force":
  addMetric();
break;
case "interactive_traffic_shell":
  addMetric();
break;
case "eternalblue_exploit":
  addMetric();
break;
case "external_db_req":
  addMetric();
break;
case "spike_in_ssh_sessions":
  addMetric();
break;
case "dns_zone_transfer":
  addMetric();
break;
case "tcp_null_fin_or_xmas_scan":
  addMetric();
break;
case "tcp_syn_scan":
  addMetric();
break;
case "rdp_brute_force":
  addMetric();
break;
case "custom.Suspicious_Network_packets":
  addMetric();
break;
case "suspicious_http_port":
  addMetric();
break;
case "unknown_public_dns_server":
  addMetric();
break;
case "potential_covert_channel":
  addMetric();
break;
default:
  debug('New Type: ' + tipe);
}

//Adding Base Metrics
app.metricAddCount("M_Det_Cnt",1); //Base Metrics 
app.metricAddSampleset("M_SmplSet_Cnt",1); //Base Metrics Sample Set
app.metricAddDataset ("M_DataSet_Cnt", 1); //Base Metrics Data Set
app.metricAddDistinct("M_Distinct_Cnt",1); //Base Metrics Distinct
app.metricAddMax("M_Max_Cnt",1); //Base Max Metrics

//commit Record for Anonymous FTP Auth Enabled & c2_web beaconing
function AFTP_c2WB() {
  var DiscoverURI = "https://youDiscoverApplianceIPAddress/" 
  var AFTP_str = Detection.description
  var AFTP_res = AFTP_str.split("]");
  var AFTP_res2 = AFTP_res[0].slice(1);
  var AFTP_alm = AFTP_res[1].split(" ");
  var AFTP_url = DiscoverURI+AFTP_alm[0].slice(1,-1);
  var AFTP_desk = AFTP_res[1].split(") ");
  var AFTP_desk2 = AFTP_desk[1];
  /*
  debug ("\n" + "node: " + AFTP_res2 + "\n" +
        "url: " + AFTP_url + "\n" +
        "desk = " + AFTP_desk2
  );
  */
  //set this to true to parse record to EXA
  const EXA_RECORDS = true;
  if (EXA_RECORDS) {
          var MDetection_row = {
              ID: Detection.id,
              Title: title,
              Kategori: "" + Detection.categories,
              RiskScore: riskScore,
              Type: tipe,
              startTime: startTime,
              updateTime: updateTime,
              endTime: endTime,
              deskripsi_01: deskripsi,
              victim: AFTP_res2
          };
          commitRecord("MDetection", MDetection_row);
  }
}  

//Exposed DB Server
function ExpDBSvr() {
  var ExpDBSvr_str = Detection.description;
  var ExpDBSvr_desk = ExpDBSvr_str.split("* **");
  var ExpDBSvr_client = ExpDBSvr_desk[1].split("**");
  var ExpDBSvr_server = ExpDBSvr_desk[2].split("**");
  var ExpDBSvr_method = ExpDBSvr_desk[3].split("** ");
  var ExpDBSvr_tabel = ExpDBSvr_desk[4].split("** ");
  var ExpDBSvr_user = ExpDBSvr_desk[5].split("** ");
  /*debug ("\n" + "desk = " + ExpDBSvr_desk[0] + "\n" + 
         "client: " + ExpDBSvr_client[1] + "\n" + 
         "server: " + ExpDBSvr_server[1] + "\n" + 
         "method: " + ExpDBSvr_method[1]+ "\n" + 
         "table: " + ExpDBSvr_tabel[1] + "\n" + 
         "user: " + ExpDBSvr_user[1]);
  */
    //set this to true to parse record to EXA
  const EXA_RECORDS =true;
  if (EXA_RECORDS) {
          var MDetection_row = {
              ID: Detection.id,
              Title: title,
              Kategori: "" + Detection.categories,
              RiskScore: riskScore,
              Type: tipe,
              startTime: startTime,
              updateTime: updateTime,
              endTime: endTime,
              deskripsi_01: deskripsi,
              offender: ExpDBSvr_client[1],
              victim: ExpDBSvr_server[1],
          };
          commitRecord("MDetection", MDetection_row);
  }
}  


//Exposed ftp n storage Server
function ExpFTPStr() {   
  var ftpstr_str = Detection.description;
  var ftpstr_desk = ftpstr_str.split("* **");
  var ftpstr_client = ftpstr_desk[1].split("**");
  var ftpstr_server = ftpstr_desk[2].split("**");
  var ftpstr_user = ftpstr_desk[3].split("**");

 debug ("\n" + "FTP String" + ftpstr_desk[0] + "\n" + 
      "FTP Client: " + ftpstr_client[1] + "\n" + 
      "FTP Server: " + ftpstr_server[1] + "\n" + 
      "FTP user: " + ftpstr_user[1]);
  
  //set this to true to parse record to EXA
  const EXA_RECORDS = true;
  if (EXA_RECORDS) {
          var MDetection_row = {
              ID: Detection.id,
              Title: title,
              Kategori: "" + Detection.categories,
              RiskScore: riskScore,
              Type: tipe,
              startTime: startTime,
              updateTime: updateTime,
              endTime: endTime,
              deskripsi_01: deskripsi,
              offendor: ftpstr_client[1],
              victim: ftpstr_server[1]
          };
          commitRecord("MDetection", MDetection_row);
  }
}

//Exposed ftp n storage Server
function StrgClnt() {   
  var strgclnt_str = Detection.description;
  var strgclnt_desk = strgclnt_str.split("* **");
  var strgclnt_client = strgclnt_desk[1].split("**");

 debug ("\n" + "Storage String" + strgclnt_desk[0] + "\n" + 
      "Storage Client: " + strgclnt_client[1]);
  
  //set this to true to parse record to EXA
  const EXA_RECORDS = true;
  if (EXA_RECORDS) {
          var MDetection_row = {
              ID: Detection.id,
              Title: title,
              Kategori: "" + Detection.categories,
              RiskScore: riskScore,
              Type: tipe,
              startTime: startTime,
              updateTime: updateTime,
              endTime: endTime,
              deskripsi_01: deskripsi,
              offendor: strgclnt_client[1]
          };
          commitRecord("MDetection", MDetection_row);
  }
}


//to Debug Change addMetric() call function to tampil() in case statements
function tampil() {
debug ("Detection Type: " + tipe + "\n" +
	     "Detection Description: " + deskripsi
	   );
}

//function for converting timestamp
function convertTimestamp(timestamp) {
  var d = new Date(timestamp),	// Convert the passed timestamp to milliseconds
		yyyy = d.getFullYear(),
		mm = ('0' + (d.getMonth() + 1)).slice(-2),	// Months are zero based. Add leading 0.
		dd = ('0' + d.getDate()).slice(-2),			// Add leading 0.
		hh = d.getHours(),
		h = hh,
		min = ('0' + d.getMinutes()).slice(-2),		// Add leading 0.
		ampm = 'AM',
		time;
			
	if (hh > 12) {
		h = hh - 12;
		ampm = 'PM';
	} else if (hh === 12) {
		h = 12;
		ampm = 'PM';
	} else if (hh == 0) {
		h = 12;
	}
	
	// ie: 2013-02-18, 8:35 AM	
	time = yyyy + '-' + mm + '-' + dd + ', ' + h + ':' + min + ' ' + ampm;
		
	return time;
}

function convertTimestamp(timestamp) {
    let thedate = new Date(timestamp);
    let months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    let MMM = months[thedate.getUTCMonth()];
    let dd = pad(thedate.getUTCDate().toString(), 2);
    let yyyy = thedate.getUTCFullYear();
    let HH = pad(thedate.getUTCHours().toString(), 2);
    let mm = pad(thedate.getUTCMinutes().toString(), 2);
    let ss = pad(thedate.getUTCSeconds().toString(), 2);
    let Z = "+0000";
	time = MMM + " " + dd + " " + yyyy + " " + HH + ":" + mm + ":" + ss + " " + Z;
    return time;
}

//Adding Detail Metrics per Detection type
function addMetric() {
   var kategori = "" + Detection.categories;
   //Add Detail Count metrics
   app.metricAddDetailCount("M_Det_Cat", kategori, 1); //Detail Metrics for M_Det_Cnt
   app.metricAddDetailCount("M_Det_Title", title, 1); //Detail Metrics for M_Det_Cnt
   app.metricAddDetailCount("M_Det_riskScore", riskScore,1); //Detail Metrics for M_Det_Cnt 
   app.metricAddDetailCount("M_Det_Description", deskripsi, 1); //Detail Metrics for M_Det_Cnt
   //Add  Detail SampleSet metrics
   app.metricAddDetailSampleset ("M_SmplSet_Cat", kategori, 1); //Detail Sample Set Metrics for M_SmplSet_Cnt
   app.metricAddDetailSampleset("M_SmplSet_Title", title, 1); //Detail Sample Set Metrics for M_SmplSet_Cnt
   app.metricAddDetailSampleset("M_SmplSet_riskScore", riskScore, 1); //Detail Sample Set Metrics for M_SmplSet_Cnt
   app.metricAddDetailSampleset("M_SmplSet_Desc", deskripsi, 1); //Detail Sample Set Metrics for M_SmplSet_Cnt
   //Add Detail DataSet metrics
   app.metricAddDetailDataset("M_DataSet_Cat", kategori, 1); 
   app.metricAddDetailDataset("M_DataSet_Title", title, 1);
   app.metricAddDetailDataset("M_DataSet_riskScore", riskScore, 1);
   app.metricAddDetailDataset("M_DataSet_Desc", deskripsi, 1);
   //Add Detail disticnt metrics
   app.metricAddDetailDistinct("M_Distinct_Cat", kategori, 1);
   app.metricAddDetailDistinct("M_Distinct_Title", title, 1);
   app.metricAddDetailDistinct("M_Disticnt_riskScore", title, 1);
   app.metricAddDetailDistinct("M_distinct_Desc", deskripsi, 1);
   //Add Max metrics
   app.metricAddDetailMax("M_Max_Cat", kategori, 1);
   app.metricAddDetailMax("M_Max_Title", title, 1);
   app.metricAddDetailMax("M_Max_riskScore", riskScore,1);
   app.metricAddDetailMax("M_Max_Desc", deskripsi, 1);
}



