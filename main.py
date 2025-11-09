                """.strip()
            else:
                info_text = f"""
🏓 *Ping Results for {host}*

*Status:* ❌ Offline or blocked
*Error:* Host is not reachable
                """.strip()
            
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
                    ports_text = "\n".join([f"• Port {port}/{proto} - {service}" for port, proto, service in open_ports[:10]])
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
                """.strip()
            else:
                info_text = f"""
🔍 *Nmap Scan Results for {target}*

*Status:* ❌ Host not found or not responding
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

    async def ipinfo(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Get information about an IP address."""
        if not context.args:
            await update.message.reply_text("Please provide an IP address. Usage: /ipinfo 8.8.8.8")
            return

        ip_address = context.args[0]
        
        try:
            socket.inet_aton(ip_address)
            
            response = requests.get(f'https://ipapi.co/{ip_address}/json/')
            ip_data = response.json()
            
            if 'error' in ip_data:
                await update.message.reply_text("❌ Error: " + ip_data.get('reason', 'Unknown error'))
                return
            
            info_text = f"""
🔍 *IP Information for {ip_address}*

*Location:*
• City: {ip_data.get('city', 'N/A')}
• Region: {ip_data.get('region', 'N/A')}
• Country: {ip_data.get('country_name', 'N/A')}

*Network:*
• ISP: {ip_data.get('org', 'N/A')}
• ASN: {ip_data.get('asn', 'N/A')}
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
            socket.inet_aton(ip_address)
            
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
                abuse_score = abuse_data.get('abuseConfidenceScore', 0)
                reputation_status = "✅ Good" if abuse_score < 25 else "⚠️ Suspicious" if abuse_score < 75 else "❌ Malicious"
                
                info_text = f"""
🛡️ *AbuseIPDB Report for {ip_address}*

*Reputation Score:* {abuse_score}/100
*Status:* {reputation_status}

*Details:*
• Total Reports: {abuse_data.get('totalReports', 0)}
• Country: {abuse_data.get('countryCode', 'N/A')}
• ISP: {abuse_data.get('isp', 'N/A')}
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
            a_records = socket.getaddrinfo(domain, None)
            ip_addresses = list(set([addr[4][0] for addr in a_records]))
            
            info_text = f"""
🌐 *DNS Lookup for {domain}*

*IP Addresses:*
{chr(10).join(f'• {ip}' for ip in ip_addresses)}
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
            domain_info = whois.whois(domain)
            
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0] if creation_date else 'N/A'
            
            expiration_date = domain_info.expiration_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0] if expiration_date else 'N/A'
            
            info_text = f"""
📋 *WHOIS Information for {domain}*

*Registrar:* {domain_info.registrar or 'N/A'}
*Creation Date:* {creation_date or 'N/A'}
*Expiration Date:* {expiration_date or 'N/A'}
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
        
        if len(file_hash) not in [32, 40, 64]:
            await update.message.reply_text("❌ Invalid hash format. Please provide MD5 (32 chars), SHA1 (40 chars), or SHA256 (64 chars) hash.")
            return

        try:
            hash_type = ['MD5', 'SHA1', 'SHA256'][[32, 40, 64].index(len(file_hash))]
            
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
                    
                    if positives == 0:
                        status = "✅ CLEAN"
                    elif positives < 5:
                        status = "⚠️ SUSPICIOUS"
                    else:
                        status = "❌ MALICIOUS"
                    
                    info_text = f"""
🛡️ *VirusTotal Hash Analysis*

*Hash:* `{file_hash}`
*Type:* {hash_type}
*Results:* {positives}/{total} engines detected
*Status:* {status}
                    """.strip()
                    
                else:
                    info_text = f"""
🛡️ *VirusTotal Hash Analysis*

*Hash:* `{file_hash}`
*Status:* ❌ Not found in database
                    """.strip()
                    
            else:
                info_text = "❌ Error connecting to VirusTotal API."

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
            vt_url = "https://www.virustotal.com/vtapi/v2/url/scan"
            params = {
                'apikey': self.virustotal_api_key,
                'url': url
            }
            
            response = requests.post(vt_url, data=params)
            
            if response.status_code == 200:
                scan_result = response.json()
                
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
                        
                        if positives == 0:
                            safety = "✅ SAFE"
                        elif positives < 5:
                            safety = "⚠️ SUSPICIOUS"
                        else:
                            safety = "❌ MALICIOUS"
                        
                        info_text = f"""
🔗 *VirusTotal URL Scan*

*URL:* {url}
*Results:* {positives}/{total} engines detected threats
*Safety Status:* {safety}
                        """.strip()
                    else:
                        info_text = f"""
🔗 *VirusTotal URL Scan*

*URL:* {url}
*Status:* 📊 Scan in progress
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
            
            try:
                ip = socket.gethostbyname(domain)
                resolution = f"✅ Resolves to {ip}"
            except:
                resolution = "❌ Does not resolve"
            
            info_text = f"""
🔗 *URL Analysis for {domain}*

*HTTPS:* {'✅ Yes' if parsed_url.scheme == 'https' else '❌ No'}
*Domain Resolution:* {resolution}
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
        
        logger.info("Password strength check performed (password hidden)")
        
        try:
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

*Strength:* {strength}
*Score:* {score}/5

*Recommendations:*
{chr(10).join(feedback) if feedback else '✅ Good password!'}
            """.strip()

            await update.message.reply_text(info_text, parse_mode='Markdown')
            
        except Exception as e:
            logger.error(f"Error checking password strength: {e}")
            await update.message.reply_text("❌ Sorry, I couldn't analyze the password.")

    async def handle_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle non-command messages."""
        text = update.message.text
        
        if text.startswith(('http://', 'https://', 'www.')):
            context.args = [text]
            await self.url_info(update, context)
        elif len(text) in [32, 40, 64] and all(c in '0123456789abcdef' for c in text.lower()):
            context.args = [text]
            await self.check_hash(update, context)
        else:
            await update.message.reply_text(
                "🤖 I'm a Cyber Security Bot! Use /help to see available commands."
            )

def main():
    """Start the bot."""
    if not BOT_TOKEN:
        logger.error("BOT_TOKEN environment variable is not set!")
        return
    
    application = Application.builder().token(BOT_TOKEN).build()
    
    bot = CyberSecurityBot()
    
    # Add command handlers
    application.add_handler(CommandHandler("start", bot.start))
    application.add_handler(CommandHandler("help", bot.help_command))
    application.add_handler(CommandHandler("ipinfo", bot.ipinfo))
    application.add_handler(CommandHandler("abusecheck", bot.abuse_check))
    application.add_handler(CommandHandler("ping", bot.ping))
    application.add_handler(CommandHandler("nmap", bot.nmap_scan))
    application.add_handler(CommandHandler("dnslookup", bot.dnslookup))
    application.add_handler(CommandHandler("whois", bot.whois_lookup))
    application.add_handler(CommandHandler("checkhash", bot.check_hash))
    application.add_handler(CommandHandler("urlinfo", bot.url_info))
    application.add_handler(CommandHandler("scanurl", bot.scan_url))
    application.add_handler(CommandHandler("passwordstrength", bot.password_strength))
    
    # Add message handler for non-command messages
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, bot.handle_message))
    
    # Start the Bot
    logger.info("🤖 Cyber Security Bot is starting...")
    print("🤖 Bot is running with Ping & Nmap features!")
    application.run_polling()

if __name__ == '__main__':
    main()
