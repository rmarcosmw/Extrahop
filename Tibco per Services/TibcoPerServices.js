/*
Modify these variables for your environment. EVENT HTTP_RESPONSE and assign it to all tibco servers.
you can change the appName accordingly to you liking
this is the uri for the TIBCO services
*/

var appName = Application("TibcoPerServices"); 
var uriSubstring = "tibco.yourdomain"; 

const myURI = HTTP.uri.split('/')

if (HTTP.payload == null) {return}

try {
    const mypay = HTTP.payload.toString();
    const myPayload = mypay.split('<ns1:RsStatus>');

    if (HTTP.uri.indexOf(uriSubstring) !== -1) {
        var tibco_services = myURI[2];
        var tibco_status = myPayload[1].slice(0,7);
        /*
        debug('\n===========================================' + '\n' +
            'client ip    : ' + Flow.client.ipaddr + ' | ' + 'DEVICE : ' + Flow.client.device + '\n' +
            'server IP    : ' + Flow.server.ipaddr + ' | ' + 'DEVICE : ' + Flow.server.device + '\n' +
            'server port  : ' + Flow.server.port + '\n' +
            'Services     : ' + tibco_services + '\n' +
            'status       : ' + tibco_status + '\n' +
            '===========================================');
        */
        appName.metricAddCount("Tibco",1);
        appName.metricAddDetailCount("Tibco_Client", Flow.client.ipaddr,1);
        appName.metricAddDetailCount("Tibco_Server", Flow.server.ipaddr,1);
        appName.metricAddDetailCount("Tibco_Server_Port", Flow.server.port.toString(),1);
        appName.metricAddDetailCount("Tibco_Services", tibco_services,1);
        appName.metricAddDetailCount("Tibco_Status", tibco_status,1)
        appName.metricAddDetailCount("Tibco_Description", Flow.client.ipaddr + ' | ' + Flow.server.ipaddr + ' | ' + Flow.server.port  + ' | ' +  tibco_services  + ' | ' + tibco_status,1)
        appName.commit();
    }
} catch (Error) {
    debug(Error);
}
