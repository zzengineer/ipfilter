<?php

define('IPFILTER_ACTIVE', true);

/* filter ips not matching any rules */
function filter_ip($ip, $rules, array $exclude_ips = array()) {
	
	if(!IPFILTER_ACTIVE) return false;
	
	/* rules split on spaces, commas, newlines */
	if(!is_array($rules))
		$rules = preg_split("/[\s,\R]+/", $rules);
		
	/* if its excluded ip it won't match */
	if(in_array($ip,$exclude_ips)) return false;

	/* if no rules present we don't filter */
	if(empty($rules)) return false;

	/* test every rule */
	foreach ($rules as $rule)
		if(ip_match($ip,$rule)) return false;

	return true;
}

/* helper, matching ips on difren rules */
function match_ip($ip, $rule) {

	/* match against x.x.x.x */	
	if($ip === $rule) return true;

	/* match against x.x.x.* */
	$wc   = substr_count($rule, '*');
	$rule = str_replace('*', '0', $rule);

	switch($wc) {
	case 0: break;
	case 1: $rule .= '/24'; break;
	case 2: $rule .= '/16'; break;
	case 3: $rule .= '/8';  break;
	default: return true; /* matching '*.*.*.*' (all) */
	}

	/* match against cidr x.x.x.x/x */
	list($subnet, $mask) = explode('/', $rule);
	if ((ip2long($ip) & ~((1 << (32 - $mask)) - 1) ) == ip2long($subnet))
		return true;

	return false;
}