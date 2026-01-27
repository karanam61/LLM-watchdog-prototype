@app.route('/api/logs', methods=['GET'])
def get_logs():
    """Fetch forensic logs for investigation (Process, Network, File)"""
    try:
        log_type = request.args.get('type')
        hostname = request.args.get('hostname')
        ip = request.args.get('ip')
        
        # Default time range: last 24 hours
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=24)
        
        # Format for DB
        start_str = start_time.isoformat()
        end_str = end_time.isoformat()
        
        logs = []
        
        if log_type == 'process':
            # Re-tokenize hostname to query DB (DB stores tokens)
            tokenized_host = tokenizer.tokenize(hostname) if hostname else None
            logs = query_process_logs(tokenized_host, start_str, end_str)
            
        elif log_type == 'network':
            # Re-tokenize IP (DB stores tokens)
            tokenized_ip = tokenizer.tokenize(ip) if ip else None
            logs = query_network_logs(tokenized_ip, start_str, end_str)

        elif log_type == 'file':
            tokenized_host = tokenizer.tokenize(hostname) if hostname else None
            logs = query_file_activity_logs(tokenized_host, start_str, end_str)
            
        elif log_type == 'windows':
            tokenized_host = tokenizer.tokenize(hostname) if hostname else None
            logs = query_windows_event_logs(tokenized_host, start_str, end_str)
            
        # DETOKENIZE RESULTS FOR ANALYST
        detokenized_logs = []
        for log in logs:
            clean_log = log.copy()
            # Detokenize common fields
            for field in ['hostname', 'username', 'source_ip', 'dest_ip']:
                if log.get(field) and isinstance(log[field], str) and (log[field].startswith('HOST-') or log[field].startswith('USER-') or log[field].startswith('IP-')):
                    clean_log[field] = tokenizer.detokenize(log[field])
            detokenized_logs.append(clean_log)
            
        return jsonify(detokenized_logs), 200

    except Exception as e:
        print(f"Error fetching logs: {e}")
        return jsonify({'error': str(e)}), 500
