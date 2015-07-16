	const IP_LOCK_ACTIVE = true; # will go into config after testphase

	private $excludedIps  = [];
    private $accessDenied = false;

	public function setExcludedIps (array $excludedIps) { $this->excludedIps = $excludedIps; }

	public function canAccessSession($row) {

		if(!self::IP_LOCK_ACTIVE) return true;

		$opnip = null; 	# session open ip
		$curip = null; 	# current ip

		$ipbound  = $row['m-ip_bound'];
		$networks = $row['m-allowed_networks'];

		$headers = ['X-MW3-PROXY-IP','HTTP_X_REAL_IP','REMOTE_ADDR'];

		foreach ($headers as $header) 
			if (isset($row['y-'. $header]) && !empty($row['y-'. $header])) {
				$opnip = $row['y-'. $header];
				break;
			}


		foreach ($headers as $header)
			if (isset($_SERVER[$header]) && !empty($_SERVER[$header])) {
				$curip = $_SERVER[$header];
				break;
			}

		/*  if its excluded ip it can do any session */
		if(in_array($curip,$this->excludedIps)) return true;

		/* session is ip bound, check against current ip */
		if($ipbound && $opnip !== $curip) return false;

		/* session is restricted to networks */
		if(empty($networks)) return true;

		/* networks split on whitespace,komma,newlines */
		$nets = preg_split("/[\s,\R]+/", $networks);

		foreach ($nets as $net)
			if($this->isIpInNet($curip,$net)) return true;

		return false;
	}

	public function isIpInNet($ip,$net) {
		
		/* match against x.x.x.x */	
		if($ip === $net) return true;

		/* match against x.x.x.* */
		$wc  = substr_count($net, '*');
		$net = str_replace('*', '0', $net);

		switch($wc) {
		case 0: break;
		case 1: $net .= '/24'; break;
		case 2: $net .= '/16'; break;
		case 3: $net .= '/8';  break;
		default: return true; /* matching '*.*.*.*' (all)  */
		}

		/* match against cidr x.x.x.x/x */
		list($subnet, $mask) = explode('/', $net);
		if ((ip2long($ip) & ~((1 << (32 - $mask)) - 1) ) == ip2long($subnet))
			return true;

		return false;
	}
