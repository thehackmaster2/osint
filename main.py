                    """.strip()
                else:
                    info_text = f"""
🏓 *Ping Results for {host}*

*Status:* ✅ Online
*Response:* Host is reachable
                    """.strip()
            else:
                info_text = f"""
🏓 *Ping Results for {host}*

*Status:* ❌ Offline or blocked
*Error:* Host is not reachable
*Details:* {result.stderr if result.stderr else 'Request timeout or host unreachable'}
                """.strip()
            
            # Edit the original message with results
            await context.bot.edit_message_text(
                chat_id=update.message.chat_id,
                message_id=status_message.message_id,
                text=info_text,
                parse_mode='Markdown'
            )
            
        except subprocess.TimeoutExpired:
            await update.message.reply_text(f"❌ Ping timeout for {host}. Host may be down or blocking ICMP requests.")
        except Exception as e:
            logger.error(f"Error pinging host: {e}")
            await update.message.reply_text(f"❌ Error pinging {host}: {str(e)}")

    async def nmap_scan(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Perform basic nmap scan (ports 1-1000)."""
        if not context.args:
            await update.message.reply_text("Please provide an IP address. Usage: /nmap 192.168.1.1")
            return

        target = context.args[0]
        
        try:
            # Validate IP/host
            socket.gethostbyname(target)
            
            status_message = await update.message.reply_text(f"🔍 Scanning {target} (ports 1-1000)...")
            
            # Perform nmap scan
            self.nm.scan(target, '1-1000', arguments='-T4 --max-retries 2 --host-timeout 120s')
            
            if target in self.nm.all_hosts():
                host_info = self.nm[target]
                
                # Get open ports
                open_ports = []
                for proto in host_info.all_protocols():
                    ports = host_info[proto].keys()
                    for port in ports:
                        state = host_info[proto][port]['state']
                        if state == 'open':
                            service = host_info[proto][port].get('name', 'unknown')
                            open_ports.append((port, proto, service))
                
                if open_ports:
                    ports_text = "\n".join([f"• Port {port}/{proto} - {service}" for port, proto, service in open_ports[:10]])  # Limit to first 10
                    if len(open_ports) > 10:
                        ports_text += f"\n• ... and {len(open_ports) - 10} more ports"
                else:
                    ports_text = "• No open ports found"
                
                info_text = f"""
🔍 *Nmap Scan Results for {target}*

*Scan Type:* Basic (ports 1-1000)
*Host Status:* {host_info.state()}
*Open Ports:*
{ports_text}

*Scan Info:*
• Protocol: TCP
• Port Range: 1-1000
• Total Ports Scanned: 1000
                """.strip()
            else:
                info_text = f"""
🔍 *Nmap Scan Results for {target}*

*Status:* ❌ Host not found or not responding
*Note:* The host may be down or blocking scan requests
                """.strip()
            
            await context.bot.edit_message_text(
                chat_id=update.message.chat_id,
                message_id=status_message.message_id,
                text=info_text,
                parse_mode='Markdown'
            )
            
        except Exception as e:
            logger.error(f"Error in nmap scan: {e}")
            await update.message.reply_text(f"❌ Error scanning {target}: {str(e)}")

    async def nmap_full_scan(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Perform full nmap scan (ports 1-65535)."""
        if not context.args:
            await update.message.reply_text("Please provide an IP address. Usage: /nmapfull 192.168.1.1")
            return

        target = context.args[0]
        
        try:
            # Warning for full scan
            warning_msg = await update.message.reply_text(
                "⚠️ *Full port scan initiated*\n"
                "This may take 5-15 minutes...\n"
                "Scanning all 65535 ports...",
                parse_mode='Markdown'
            )
            
            # Validate IP/host
            socket.gethostbyname(target)
            
            # Perform nmap scan with longer timeout
            self.nm.scan(target, '1-65535', arguments='-T4 --max-retries 1 --host-timeout 600s')
            
            if target in self.nm.all_hosts():
                host_info = self.nm[target]
                
                # Get open ports
                open_ports = []
                for proto in host_info.all_protocols():
                    ports = host_info[proto].keys()
                    for port in ports:
                        state = host_info[proto][port]['state']
                        if state == 'open':
                            service = host_info[proto][port].get('name', 'unknown')
                            product = host_info[proto][port].get('product', '')
                            version = host_info[proto][port].get('version', '')
                            open_ports.append((port, proto, service, product, version))
                
                if open_ports:
                    ports_text = "\n".join([f"• Port {port}/{proto} - {service} {product} {version}".strip() 
                                          for port, proto, service, product, version in open_ports[:15]])  # Limit to first 15
                    if len(open_ports) > 15:
                        ports_text += f"\n• ... and {len(open_ports) - 15} more ports"
                else:
                    ports_text = "• No open ports found"
                
                info_text = f"""
🔍 *Full Nmap Scan Results for {target}*

*Scan Type:* Comprehensive (all ports)
*Host Status:* {host_info.state()}
*Open Ports:*
{ports_text}

*Scan Info:*
• Protocol: TCP
• Port Range: 1-65535
• Total Ports Scanned: 65535
• Scan Duration: Several minutes
                """.strip()
            else:
                info_text = f"""
🔍 *Full Nmap Scan Results for {target}*

*Status:* ❌ Host not found or not responding
*Note:* The host may be down or blocking scan requests
                """.strip()
            
            await context.bot.edit_message_text(
                chat_id=update.message.chat_id,
                message_id=warning_msg.message_id,
                text=info_text,
                parse_mode='Markdown'
            )
            
        except Exception as e:
            logger.error(f"Error in full nmap scan: {e}")
            await update.message.reply_text(f"❌ Error scanning {target}: {str(e)}")

    async def scan_file(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle file uploads for virus scanning."""
        if not update.message.document and not update.message.photo:
            await update.message.reply_text(
                "📎 Please upload a file or image for scanning.\n\n"
                "*Supported files:*\n"
                "• Documents (PDF, DOC, DOCX)\n" 
                "• Images (JPG, PNG, GIF)\n"
                "• Archives (ZIP, RAR)\n"
                "• Executables (EXE, MSI)\n"
                "• And many more...\n\n"
                "*How to use:*\n"
                "1. Click the 📎 attachment icon\n"
                "2. Select your file\n"
                "3. Send it to me for analysis",
                parse_mode='Markdown'
            )
            return
        
        try:
            status_message = await update.message.reply_text("🔄 Downloading and analyzing file...")
            
            # Get file information
            if update.message.document:
                file = await update.message.document.get_file()
                file_name = update.message.document.file_name
                file_size = update.message.document.file_size
            elif update.message.photo:
                # Get the highest quality photo
                file = await update.message.photo[-1].get_file()
                file_name = "image.jpg"
                file_size = "Unknown"
            
            # Check file size (VirusTotal limit is 32MB for public API)
            if file_size and file_size > 32 * 1024 * 1024:
                await context.bot.edit_message_text(
                    chat_id=update.message.chat_id,
                    message_id=status_message.message_id,
                    text="❌ File too large. Maximum size is 32MB for VirusTotal analysis."
                )
                return
            
            # Download file to temporary location
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                await file.download_to_drive(temp_file.name)
                
                # Calculate file hash
                with open(temp_file.name, 'rb') as f:
                    file_content = f.read()
                    file_hash = hashlib.sha256(file_content).hexdigest()
                
                # Upload to VirusTotal for analysis
                vt_url = "https://www.virustotal.com/vtapi/v2/file/scan"
                files = {'file': (file_name, file_content)}
                params = {'apikey': self.virustotal_api_key}
                
                upload_response = requests.post(vt_url, files=files, params=params)
                
                if upload_response.status_code == 200:
                    upload_result = upload_response.json()
                    
                    # Now get the analysis report
                    report_url = "https://www.virustotal.com/vtapi/v2/file/report"
                    report_params = {
                        'apikey': self.virustotal_api_key,
                        'resource': file_hash
                    }
                    
                    # Wait a moment for analysis to complete, then get report
                    import time
                    time.sleep(2)
                    
                    report_response = requests.get(report_url, params=report_params)
                    
                    if report_response.status_code == 200:
                        report = report_response.json()
                        
                        if report['response_code'] == 1:
                            positives = report['positives']
                            total = report['total']
                            scan_date = report.get('scan_date', 'Unknown')
                            
                            # Determine threat level
                            if positives == 0:
                                threat_level = "✅ CLEAN"
                                emoji = "✅"
                            elif positives < 5:
                                threat_level = "⚠️ SUSPICIOUS"
                                emoji = "⚠️"
                            else:
                                threat_level = "❌ MALICIOUS"
                                emoji = "❌"
                            
                            # Get some scanner results
                            scans = report.get('scans', {})
                            detections = []
                            for scanner, result in list(scans.items())[:5]:  # Show first 5 detections
                                if result.get('detected', False):
                                    detections.append(f"• {scanner}: {result.get('result', 'Malicious')}")
                            
                            detections_text = "\n".join(detections) if detections else "• No specific detections listed"
                            
                            info_text = f"""
🛡️ *VirusTotal File Analysis*

*File:* {file_name}
*Size:* {file_size} bytes
*SHA256:* `{file_hash}`
*Scan Date:* {scan_date}

*Results:* {positives}/{total} engines detected
*Status:* {threat_level}

*Detection Ratio:* {positives}/{total} ({positives/total*100:.1f}%)
{emoji} *Verdict:* {threat_level.split(' ')[1]}

*Top Detections:*
{detections_text}

*Permalink:* {report.get('permalink', 'Not available')}
                            """.strip()
                        else:
                            info_text = f"""
🛡️ *VirusTotal File Analysis*

*File:* {file_name}
*Size:* {file_size} bytes
*SHA256:* `{file_hash}`

*Status:* 📊 Analysis in progress
*Message:* File uploaded successfully. Analysis may take a few minutes.
*Note:* Use /checkhash {file_hash} later to check results.
                            """.strip()
                    else:
                        info_text = "❌ Error retrieving file analysis report."
                else:
                    info_text = "❌ Error uploading file to VirusTotal."
            
            # Clean up temporary file
            os.unlink(temp_file.name)
            
            await context.bot.edit_message_text(
                chat_id=update.message.chat_id,
                message_id=status_message.message_id,
                text=info_text,
                parse_mode='Markdown'
            )
            
        except Exception as e:
            logger.error(f"Error scanning file: {e}")
            await update.message.reply_text(f"❌ Error analyzing file: {str(e)}")

    # Keep all your existing methods (ipinfo, abuse_check, dnslookup, whois_lookup, check_hash, scan_url, url_info, password_strength, handle_message)
    # ... [Include all the previous methods here without changes] ...

    async def ipinfo(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Get information about an IP address."""
        if not context.args:
            await update.message.reply_text("Please provide an IP address. Usage: /ipinfo 8.8.8.8")
            return

        ip_address = context.args[0]
        
        try:
            # Validate IP address
            socket.inet_aton(ip_address)
            
            # Get IP information from ipapi.co
            response = requests.get(f'https://ipapi.co/{ip_address}/json/')
            ip_data = response.json()
            
            if 'error' in ip_data:
                await update.message.reply_text("❌ Error: " + ip_data.get('reason', 'Unknown error'))
                return
            
            # Format the response
            info_text = f"""
🔍 *IP Information for {ip_address}*

*Location:*
• City: {ip_data.get('city', 'N/A')}
• Region: {ip_data.get('region', 'N/A')}
• Country: {ip_data.get('country_name', 'N/A')}
• Postal Code: {ip_data.get('postal', 'N/A')}

*Network:*
• ISP: {ip_data.get('org', 'N/A')}
• ASN: {ip_data.get('asn', 'N/A')}

*Technical:*
• Timezone: {ip_data.get('timezone', 'N/A')}
• Currency: {ip_data.get('currency', 'N/A')}
            """.strip()

            await update.message.reply_text(info_text, parse_mode='Markdown')
            
        except socket.error:
            await update.message.reply_text("❌ Invalid IP address format.")
        except Exception as e:
            logger.error(f"Error fetching IP info: {e}")
            await update.message.reply_text("❌ Sorry, I couldn't fetch information for that IP.")

    async def abuse_check(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Check IP against AbuseIPDB."""
        if not context.args:
            await update.message.reply_text("Please provide an IP address. Usage: /abusecheck 192.168.1.1")
            return

        ip_address = context.args[0]
        
        try:
            # Validate IP address
            socket.inet_aton(ip_address)
            
            # AbuseIPDB API call
            url = 'https://api.abuseipdb.com/api/v2/check'
            headers = {
                'Accept': 'application/json',
                'Key': self.abuseipdb_api_key
            }
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90
            }
            
            response = requests.get(url, headers=headers, params=params)
            data = response.json()
            
            if 'data' in data:
                abuse_data = data['data']
                
                # Calculate reputation score (0-100, higher is better)
                abuse_score = abuse_data.get('abuseConfidenceScore', 0)
                reputation_status = "✅ Good" if abuse_score < 25 else "⚠️ Suspicious" if abuse_score < 75 else "❌ Malicious"
                
                info_text = f"""
🛡️ *AbuseIPDB Report for {ip_address}*

*Reputation Score:* {abuse_score}/100
*Status:* {reputation_status}

*Details:*
• Total Reports: {abuse_data.get('totalReports', 0)}
• Last Reported: {abuse_data.get('lastReportedAt', 'Never')}
• Country: {abuse_data.get('countryCode', 'N/A')}
• ISP: {abuse_data.get('isp', 'N/A')}
• Domain: {abuse_data.get('domain', 'N/A')}

*Usage Type:* {abuse_data.get('usageType', 'N/A')}
*Is Whitelisted:* {'✅ Yes' if abuse_data.get('isWhitelisted', False) else '❌ No'}
                """.strip()
                
                await update.message.reply_text(info_text, parse_mode='Markdown')
            else:
                await update.message.reply_text("❌ Could not retrieve abuse information for this IP.")
                
        except socket.error:
            await update.message.reply_text("❌ Invalid IP address format.")
        except Exception as e:
            logger.error(f"Error checking abuse IP: {e}")
            await update.message.reply_text("❌ Sorry, I couldn't check this IP with AbuseIPDB.")

    async def dnslookup(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Perform DNS lookup for a domain."""
        if not context.args:
            await update.message.reply_text("Please provide a domain. Usage: /dnslookup example.com")
            return

        domain = context.args[0]
        
        try:
            # Get A records
            a_records = socket.getaddrinfo(domain, None)
            ip_addresses = list(set([addr[4][0] for addr in a_records]))
            
            info_text = f"""
🌐 *DNS Lookup for {domain}*

*A Records (IP Addresses):*
{chr(10).join(f'• {ip}' for ip in ip_addresses)}

*Additional Info:*
• Resolved {len(ip_addresses)} IP address(es)
            """.strip()

            await update.message.reply_text(info_text, parse_mode='Markdown')
            
        except Exception as e:
            logger.error(f"Error in DNS lookup: {e}")
            await update.message.reply_text("❌ Sorry, I couldn't perform DNS lookup for that domain.")

    async def whois_lookup(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Perform WHOIS lookup for a domain."""
        if not context.args:
            await update.message.reply_text("Please provide a domain. Usage: /whois example.com")
            return

        domain = context.args[0]
        
        try:
            # Perform WHOIS lookup
            domain_info = whois.whois(domain)
            
            # Format dates properly
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0] if creation_date else 'N/A'
            
            expiration_date = domain_info.expiration_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0] if expiration_date else 'N/A'
            
            info_text = f"""
📋 *WHOIS Information for {domain}*

*Registrar:*
• Registrar: {domain_info.registrar or 'N/A'}

*Dates:*
• Creation Date: {creation_date or 'N/A'}
• Expiration Date: {expiration_date or 'N/A'}

*Name Servers:*
{chr(10).join(f'• {ns}' for ns in (domain_info.name_servers or ['N/A'][:3]))}
            """.strip()

            await update.message.reply_text(info_text, parse_mode='Markdown')
            
        except Exception as e:
            logger.error(f"Error in WHOIS lookup: {e}")
            await update.message.reply_text("❌ Sorry, I couldn't fetch WHOIS information for that domain.")

    async def check_hash(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Check file hash against VirusTotal."""
        if not context.args:
            await update.message.reply_text("Please provide a hash. Usage: /checkhash <MD5/SHA1/SHA256>")
            return

        file_hash = context.args[0].lower()
        
        # Validate hash format
        if len(file_hash) not in [32, 40, 64]:  # MD5, SHA1, SHA256 lengths
            await update.message.reply_text("❌ Invalid hash format. Please provide MD5 (32 chars), SHA1 (40 chars), or SHA256 (64 chars) hash.")
            return

        try:
            hash_type = ['MD5', 'SHA1', 'SHA256'][[32, 40, 64].index(len(file_hash))]
            
            # VirusTotal API call
            url = "https://www.virustotal.com/vtapi/v2/file/report"
            params = {
                'apikey': self.virustotal_api_key,
                'resource': file_hash
            }
            
            response = requests.get(url, params=params)
            
            if response.status_code == 200:
                result = response.json()
                
                if result['response_code'] == 1:
                    positives = result['positives']
                    total = result['total']
                    
                    # Determine status
                    if positives == 0:
                        status = "✅ CLEAN"
                        status_emoji = "✅"
                    elif positives < 5:
                        status = "⚠️ SUSPICIOUS"
                        status_emoji = "⚠️"
                    else:
                        status = "❌ MALICIOUS"
                        status_emoji = "❌"
                    
                    # Get scan date
                    scan_date = result.get('scan_date', 'Unknown')
                    
                    info_text = f"""
🛡️ *VirusTotal Hash Analysis*

*Hash:* `{file_hash}`
*Type:* {hash_type}
*Scan Date:* {scan_date}

*Results:* {positives}/{total} engines detected
*Status:* {status}

*Detection Ratio:* {positives}/{total} ({positives/total*100:.1f}%)
{status_emoji} *Verdict:* {status.split(' ')[1]}
                    """.strip()
                    
                else:
                    info_text = f"""
🛡️ *VirusTotal Hash Analysis*

*Hash:* `{file_hash}`
*Type:* {hash_type}

*Status:* ❌ Not found in VirusTotal database
*Message:* This hash is not present in our dataset
                    """.strip()
                    
            else:
                info_text = "❌ Error connecting to VirusTotal API. Please try again later."

            await update.message.reply_text(info_text, parse_mode='Markdown')
            
        except Exception as e:
            logger.error(f"Error checking hash: {e}")
            await update.message.reply_text("❌ Sorry, I couldn't check the hash with VirusTotal.")

    async def scan_url(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Scan URL with VirusTotal."""
        if not context.args:
            await update.message.reply_text("Please provide a URL. Usage: /scanurl https://example.com")
            return

        url = context.args[0]
        
        try:
            # VirusTotal URL scan
            vt_url = "https://www.virustotal.com/vtapi/v2/url/scan"
            params = {
                'apikey': self.virustotal_api_key,
                'url': url
            }
            
            # First, submit URL for scanning
            response = requests.post(vt_url, data=params)
            
            if response.status_code == 200:
                scan_result = response.json()
                
                # Now get the report
                report_url = "https://www.virustotal.com/vtapi/v2/url/report"
                report_params = {
                    'apikey': self.virustotal_api_key,
                    'resource': url
                }
                
                report_response = requests.get(report_url, params=report_params)
                
                if report_response.status_code == 200:
                    report = report_response.json()
                    
                    if report['response_code'] == 1:
                        positives = report['positives']
                        total = report['total']
                        
                        # Determine safety status
                        if positives == 0:
                            safety = "✅ SAFE"
                            emoji = "✅"
                        elif positives < 5:
                            safety = "⚠️ SUSPICIOUS"
                            emoji = "⚠️"
                        else:
                            safety = "❌ MALICIOUS"
                            emoji = "❌"
                        
                        info_text = f"""
🔗 *VirusTotal URL Scan*

*URL:* {url}
*Scan Date:* {report.get('scan_date', 'Unknown')}

*Results:* {positives}/{total} engines detected threats
*Safety Status:* {safety}

*Detection Ratio:* {positives}/{total} ({positives/total*100:.1f}%)
{emoji} *Verdict:* {safety.split(' ')[1]}
                        """.strip()
                    else:
                        info_text = f"""
🔗 *VirusTotal URL Scan*

*URL:* {url}
*Status:* 📊 Scan in progress or not available
*Message:* The URL is being analyzed. Try again in a few moments.
                        """.strip()
                else:
                    info_text = "❌ Error retrieving URL scan report."
            else:
                info_text = "❌ Error submitting URL for scanning."

            await update.message.reply_text(info_text, parse_mode='Markdown')
            
        except Exception as e:
            logger.error(f"Error scanning URL: {e}")
            await update.message.reply_text("❌ Sorry, I couldn't scan the URL with VirusTotal.")

    async def url_info(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Analyze a URL for safety."""
        if not context.args:
            await update.message.reply_text("Please provide a URL. Usage: /urlinfo https://example.com")
            return

        url = context.args[0]
        
        try:
            parsed_url = urlparse(url)
            
            if not parsed_url.scheme:
                url = 'https://' + url
                parsed_url = urlparse(url)
            
            domain = parsed_url.netloc
            
            # Check if domain resolves
            try:
                ip = socket.gethostbyname(domain)
                resolution = f"✅ Resolves to {ip}"
            except:
                resolution = "❌ Does not resolve"
            
            # Suspicious TLDs
            suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'xyz', 'top', 'club', 'loan']
            is_suspicious_tld = domain.split('.')[-1] in suspicious_tlds
            
            info_text = f"""
🔗 *URL Analysis for {domain}*

*URL Components:*
• Scheme: {parsed_url.scheme}
• Domain: {parsed_url.netloc}
• Path: {parsed_url.path or '/'}

*Security Analysis:*
• HTTPS: {'✅ Yes' if parsed_url.scheme == 'https' else '❌ No'}
• Domain Resolution: {resolution}
• TLD Risk: {'⚠️ Suspicious' if is_suspicious_tld else '✅ Normal'}

*Recommendations:*
• Use /scanurl for deep VirusTotal analysis
• Always verify URLs before clicking!
• Check for HTTPS and valid certificates
            """.strip()

            await update.message.reply_text(info_text, parse_mode='Markdown')
            
        except Exception as e:
            logger.error(f"Error analyzing URL: {e}")
            await update.message.reply_text("❌ Sorry, I couldn't analyze that URL.")

    async def password_strength(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Check password strength."""
        if not context.args:
            await update.message.reply_text("Please provide a password. Usage: /passwordstrength MyPassword123!")
            return

        password = ' '.join(context.args)
        
        # Remove the password from logs for security
        logger.info("Password strength check performed (password hidden)")
        
        try:
            # Password strength analysis
            score = 0
            feedback = []
            
            if len(password) >= 8:
                score += 1
            else:
                feedback.append("❌ Too short (min 8 characters)")
                
            if any(c.islower() for c in password):
                score += 1
            else:
                feedback.append("❌ Add lowercase letters")
                
            if any(c.isupper() for c in password):
                score += 1
            else:
                feedback.append("❌ Add uppercase letters")
                
            if any(c.isdigit() for c in password):
                score += 1
            else:
                feedback.append("❌ Add numbers")
                
            if any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?`~' for c in password):
                score += 1
            else:
                feedback.append("❌ Add special characters")
            
            # Strength assessment
            if score == 5:
                strength = "💪 Very Strong"
            elif score == 4:
                strength = "👍 Strong"
            elif score == 3:
                strength = "⚠️ Moderate"
            else:
                strength = "❌ Weak"
            
            info_text = f"""
🔐 *Password Strength Analysis*

*Length:* {len(password)} characters
*Strength:* {strength}
*Score:* {score}/5

*Recommendations:*
{chr(10).join(feedback) if feedback else '✅ Good password!'}

*Security Tip:* Use a password manager and enable 2FA!
            """.strip()

            await update.message.reply_text(info_text, parse_mode='Markdown')
            
        except Exception as e:
            logger.error(f"Error checking password strength: {e}")
            await update.message.reply_text("❌ Sorry, I couldn't analyze the password.")

    async def handle_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle non-command messages."""
        text = update.message.text
        
        # Check if message looks like a URL
        if text.startswith(('http://', 'https://', 'www.')):
            context.args = [text]
            await self.url_info(update, context)
        # Check if message looks like a hash
        elif len(text) in [32, 40, 64] and all(c in '0123456789abcdef' for c in text.lower()):
            context.args = [text]
            await self.check_hash(update, context)
        else:
            await update.message.reply_text(
                "🤖 I'm a Cyber Security Bot! Use /help to see available commands."
            )

def main():
    """Start the bot."""
    # Check if token is available
    if not BOT_TOKEN:
        logger.error("BOT_TOKEN environment variable is not set!")
        return
    
    # Create the Application
    application = Application.builder().token(BOT_TOKEN).build()
    
    bot = CyberSecurityBot()
    
    # Add command handlers
    application.add_handler(CommandHandler("start", bot.start))
    application.add_handler(CommandHandler("help", bot.help_command))
    application.add_handler(CommandHandler("ipinfo", bot.ipinfo))
    application.add_handler(CommandHandler("abusecheck", bot.abuse_check))
    application.add_handler(CommandHandler("ping", bot.ping))
    application.add_handler(CommandHandler("nmap", bot.nmap_scan))
    application.add_handler(CommandHandler("nmapfull", bot.nmap_full_scan))
    application.add_handler(CommandHandler("dnslookup", bot.dnslookup))
    application.add_handler(CommandHandler("whois", bot.whois_lookup))
    application.add_handler(CommandHandler("checkhash", bot.check_hash))
    application.add_handler(CommandHandler("urlinfo", bot.url_info))
    application.add_handler(CommandHandler("scanurl", bot.scan_url))
    application.add_handler(CommandHandler("passwordstrength", bot.password_strength))
    
    # Add file handler for document and photo uploads
    application.add_handler(MessageHandler(filters.Document.ALL, bot.scan_file))
    application.add_handler(MessageHandler(filters.PHOTO, bot.scan_file))
    
    # Add message handler for non-command messages
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, bot.handle_message))
    
    # Start the Bot
    logger.info("🤖 Cyber Security Bot is starting...")
    print("🤖 Bot is running with full features!")
    print("🔧 Features enabled: VirusTotal + AbuseIPDB + Nmap + File Scanning")
    application.run_polling()

if __name__ == '__main__':
    main()
