# 🛡️ Splunk HTTP Log Analysis

A hands-on SOC mini project using Splunk to analyze Zeek-style HTTP logs. This lab demonstrates core blue-team skills such as log ingestion, HTTP traffic analysis, detection of server/client errors, identifying suspicious User-Agents, analyzing large file transfers, and detecting malicious URI access attempts. Ideal for developing practical SOC investigation and detection engineering skills.
---

## 🎯 Objective  
To ingest and analyze **HTTP logs** in Splunk, identify server/client errors, detect suspicious User-Agents and URIs, monitor large file transfers, and build practical SOC detection and investigation skills.
---

## 🧩 Lab Setup  
- **Tool:** Splunk cloud  
- **index:** `main`  
- **source:** `http_lab`  
- **Sourcetype:** `zeek:http`  

---

## ⚙️ Task 1: Searching HTTP Events  

### 🕵️ Retrieve all HTTP logs  
```spl
index=main sourcetype="zeek:http"
```

---

## 📊 Task 2: Find the top 10 endpoints generating web traffic  

### 🔹 Identifies the top IP addresses sending the highest number of HTTP requests.  
```spl
index=main sourcetype="zeek:http"
| stats count by "id.orig_h"
| sort -count
| head 10
```

---

## ⚠️ Task 3:Count the number of server errors - status code(5xx)  
```spl
index=main sourcetype="zeek:http" status_code>=500 status_code<600
| stats count as server_errors
```

---

## ⚠️ Task 4: Identify User-Agents associated with possible scripted attacks 

### 🔹 Looks for HTTP requests coming from known malicious automation tools
```spl
index=main sourcetype="zeek:http" user_agent IN ("sqlmap/1.5.1", "curl/7.68.0", "python-requests/2.25.1", "botnet-checker/1.0")
| stats count by user_agent

```
---

## ⚠️ Task 5: Detect large file transfers

### 🔹 Finds HTTP responses where the server sent large files (over 500 KB).  
```spl
index=main sourcetype="zeek:http" resp_body_len>500000
| table ts "id.orig_h" "id.resp_h" uri resp_body_len
| sort -resp_body_len
```
---

## ⚠️ Task 6: Detect suspicious URIs accessed  
```spl
index=main sourcetype="zeek:http" uri IN ("/admin","/shell.php","/etc/passwd")
| stats count by uri, "id.orig_h"
```

---

## 🖼 Dashboard Screenshots 

![image alt](https://github.com/sudarsan143/Splunk-HTTP-Log-Analysis/blob/aba12d3af67ecdf3bf0be6339ebe79e405406cb6/top%2010%20endpoints%20generating%20web%20traffic.png)
![image alt](https://github.com/sudarsan143/Splunk-HTTP-Log-Analysis/blob/aba12d3af67ecdf3bf0be6339ebe79e405406cb6/server_errors.png)
![image alt](https://github.com/sudarsan143/Splunk-HTTP-Log-Analysis/blob/aba12d3af67ecdf3bf0be6339ebe79e405406cb6/User-Agents%20associated%20with%20possible%20scripted%20attacks.png)
![image alt](https://github.com/sudarsan143/Splunk-HTTP-Log-Analysis/blob/aba12d3af67ecdf3bf0be6339ebe79e405406cb6/large%20file%20transfers%20(greater%20than%20500%20KB).png)
![image alt](https://github.com/sudarsan143/Splunk-HTTP-Log-Analysis/blob/aba12d3af67ecdf3bf0be6339ebe79e405406cb6/suspicious%20URIs%20accessed.png)

---



---

## 🏁 Conclusion  
This project enabled me to deepen my SOC analysis skills by:  
- Performing comprehensive SSH authentication monitoring using Splunk 
- Identifying brute-force patterns, anomalous login behaviors, and suspicious access attempts
- Correlating successful logins with prior failures to uncover potential account compromise
- Profiling attacker IPs through geo-enrichment and interpreting trends with dashboards and time-based visualizations 

---
---

## 🏁 Final Thoughts  
- This project strengthened my practical SOC workflow by simulating real-world SSH attack scenarios and investigating them through Splunk. From detecting brute-force attempts to analyzing authenticated sessions, the end-to-end process reinforced how SIEM data can reveal early signs of compromise. The dashboards, alerts, and correlation logic built during this project provide a strong foundation for continuous monitoring and rapid incident response in an enterprise environment.


---

## 🔖 Tags  
`#Splunk` `#CyberSecurity` `#SOC` `#SIEM` `#SSHLogs` `#ThreatDetection` `#BlueTeam` `#HandsOnLearning`

