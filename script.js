function main() { 
    if (document.getElementById("search").value)
        search=document.getElementById("search").value
    else {
        const params = new Proxy(new URLSearchParams(window.location.search), {
            get: (searchParams, prop) => searchParams.get(prop),
        });
        search=params.search
    }
    if (search)
        open_threat_intel(search)
  }

  function open_threat_intel(search) {
    ///https://stackoverflow.com/questions/3891641/regex-test-only-works-every-other-time
    const ipv4_regex =/^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}$/;   
    const ipv6_regex = /^(?:(?:[a-fA-F\d]{1,4}:){7}(?:[a-fA-F\d]{1,4}|:)|(?:[a-fA-F\d]{1,4}:){6}(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|:[a-fA-F\d]{1,4}|:)|(?:[a-fA-F\d]{1,4}:){5}(?::(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[a-fA-F\d]{1,4}){1,2}|:)|(?:[a-fA-F\d]{1,4}:){4}(?:(?::[a-fA-F\d]{1,4}){0,1}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[a-fA-F\d]{1,4}){1,3}|:)|(?:[a-fA-F\d]{1,4}:){3}(?:(?::[a-fA-F\d]{1,4}){0,2}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[a-fA-F\d]{1,4}){1,4}|:)|(?:[a-fA-F\d]{1,4}:){2}(?:(?::[a-fA-F\d]{1,4}){0,3}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[a-fA-F\d]{1,4}){1,5}|:)|(?:[a-fA-F\d]{1,4}:){1}(?:(?::[a-fA-F\d]{1,4}){0,4}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[a-fA-F\d]{1,4}){1,6}|:)|(?::(?:(?::[a-fA-F\d]{1,4}){0,5}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[a-fA-F\d]{1,4}){1,7}|:)))(?:%[0-9a-zA-Z]{1,})?$/;     
    const md5_regx=/^[0-9a-f]{32}$/i
    const sha256_regex=/^[0-9a-f]{64}$/i
    const fqdn_regex=/^(?!:\/\/)(?=.{1,255}$)((.{1,63}\.){1,127}(?![0-9]*$)[a-z0-9-]+\.?)$/i
    const cve_regex=/CVE-\d{4}-\d{4,7}/i


    if (md5_regx.test(search) || sha256_regex.test(search)) {
        window.open(`https://www.virustotal.com/gui/search/${search}`)
        window.open(`https://exchange.xforce.ibmcloud.com/search/${search}`)
        window.open(`https://opentip.kaspersky.com/${search}/?tab=lookup`)
        //window.open(`https://www.hybrid-analysis.com/search?query=${search}`)
        window.open(`https://www.joesandbox.com/search?q=${search}`)
        window.open(`https://app.recordedfuture.com/live/sc/entity/hash:${search}`)
        window.open(`https://www.echotrail.io/insights/search/${search}/`)
    }

    if (ipv4_regex.test(search) || ipv6_regex.test(search))  {
        window.open(`https://www.abuseipdb.com/check/${search}`)
        window.open(`https://www.criminalip.io/asset/search?query=${search}`)
        window.open(`https://app.recordedfuture.com/live/sc/entity/ip:${search}`)
        window.open(`https://www.virustotal.com/gui/search/${search}`)
        window.open(`https://exchange.xforce.ibmcloud.com/search/${search}`)
        window.open(`https://opentip.kaspersky.com/${search}/?tab=lookup`)

    }
    if (fqdn_regex.test(search )) {
        window.open(`https://www.abuseipdb.com/check/${search}`)
        window.open(`https://www.criminalip.io/asset/search?query=${search}`)
        window.open(`https://www.virustotal.com/gui/search/${search}`)
        window.open(`https://exchange.xforce.ibmcloud.com/search/${search}`)
        window.open(`https://opentip.kaspersky.com/${search}/?tab=lookup`)
    }
    if(cve_regex.test(search)) {
      window.open(`https://www.cve.org/CVERecord?id=${search.toUpperCase()}`)
    }
  }