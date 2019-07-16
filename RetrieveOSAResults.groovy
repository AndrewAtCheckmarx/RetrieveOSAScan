@Grapes([
        @Grab(group='org.codehaus.groovy.modules.http-builder', module='http-builder', version='0.7.1' ),
        @Grab(group='org.apache.httpcomponents', module='httpclient', version='4.3.5'),
        @Grab(group='org.apache.httpcomponents', module='httpmime', version='4.3.5')
])


import groovyx.net.http.*
import org.apache.http.entity.*
import org.apache.http.entity.mime.MultipartEntity
import org.apache.http.entity.mime.HttpMultipartMode
import org.apache.http.entity.mime.content.InputStreamBody
import org.apache.http.entity.mime.content.StringBody


def	user = args[0]
def pword = args[1]
def proj2Scan = args[2]
def projId2Scan = 0


String host = "http://192.168.1.14"
String arm = host + ":8081"

def site = new RESTClient( host )
def siteArm = new RESTClient( arm )

site.auth.basic '${user}', '${pword}'
def body = [grant_type:'password']
def accessToken

File file = new File("results.json")


// *************************************************
// ***           Authenticate                    ***
// *************************************************

try {

    site.post( path: '/cxrestapi/auth/identity/connect/token', body: [grant_type:'password', username:"${user}" ,password:"${pword}", scope:'sast_rest_api', client_id:'resource_owner_client', client_secret:'014DF517-39D1-4453-B7B3-9930C563627C'])
            { resp, reader ->
                accessToken = reader['access_token']
            }
    site.auth.basic "",""
} catch (groovyx.net.http.HttpResponseException ex) {
    println("Cannot connect to " + host)
    System.exit(1)

} catch (java.net.ConnectException ex) {
    println("Cannot connect to " + host)
    System.exit(2)
}




// *************************************************
// ***           Retrieve list of Projects       ***
// *************************************************

def projId = 0;
try
{
    println ("\n${accessToken}\n")
    site.get(path: '/cxrestapi/projects',
            headers: ['Authorization': "Bearer ${accessToken}"],
            query: [projectName: 'BookStoreJava']
    )
            { resp, reader ->
println(reader)
                for(proj in reader)
                {
                    if (proj2Scan == proj['name'])
                    {
                        pName = proj['name']
                        //println("Project Name: ${pName}")
                        projId2Scan = proj['id']
                        //println("Project Id: ${projId2Scan}")
                    }
                }

                println("\n\n Retrieve scan details for ${pName} ${projId2Scan} \n\n")
            }
} catch (groovyx.net.http.HttpResponseException ex) {

    println("Cannot connect to " + host)
    System.exit(3)

} catch (java.net.ConnectException ex) {
    println("Cannot connect to " + host)
    System.exit(4)
}


// *****************************************************************
// ***  Submit OSA Scan                                          ***
// *****************************************************************
 //scanIDval = submitScan(host, projId2Scan, accessToken)


// *****************************************************************
// ***   Retrieve list of Scans for a Project                    ***
// *****************************************************************

println("\n Retrieve list of Scans  for " + projId2Scan  )

try{
    site.get(path: '/cxrestapi/osa/scans',
            headers: ['Authorization': "Bearer ${accessToken}", 'requestContentType': "JSON"],
            query: [projectId: projId2Scan])
            { resp2, json ->
                def String rVal = ""

                rVal << json
                println(json[0].id)
                scanIDval = json[0].id
                println("\n scanIDval " + scanIDval)
            }
} catch (groovyx.net.http.HttpResponseException ex) {
    println("Cannot connect to " + host)
    System.exit(7)

} catch (java.net.ConnectException ex) {
    println("Cannot connect to " + host)
    System.exit(8)
}



// **********************************************************************
// ***   Retrieve list of Vulnerable Libraries for specific scan       ***
// **********************************************************************

try{
    println("\n Retrieve Libraries for " + scanIDval)
    site.get(path: '/cxrestapi/osa/libraries',
            headers: ['Authorization': "Bearer ${accessToken}", 'requestContentType': "JSON"],
            query: [scanId: scanIDval])
            { resp2, reader3 ->
                // lets split the lines up for readability
              //  println(reader3)
                for (item in reader3)
                {
                    String thisItem = item
                    libName = item['name']
                    println(libName)
                    libId = item['id']
                    println(libId)
                    item2 =	thisItem.replaceAll("\\r?\\n", ' ')
                    def json3 = new groovy.json.JsonBuilder()
                    json3.call(reader3)

                   file.write("\r\n Libraries\n" + json3.toPrettyString());
                }
            }
} catch (groovyx.net.http.HttpResponseException ex) {
    println("Cannot connect to " + host)
    System.exit(9)

} catch (java.net.ConnectException ex) {
    println("Cannot connect to " + host)
    System.exit(10)
}

// /cxarm/policymanager/projects/{id}/violationscalculation
// *****************************************************************
// ***   Calculate Policy Violations                             ***
// *****************************************************************

// rCode = calculatePolicy(host, projId2Scan, accessToken)

// println("\ncalculatePolicy " + rCode )

// **********************************************************************
// ***   Retrieve list of Policy Violations for specific project      ***
// **********************************************************************

try{
    println("\n Retrieve Policy Violations for /cxarm/policymanager/projects/${projId2Scan}/violations" )

    siteArm.get(path: "/cxarm/policymanager/projects/${projId2Scan}/violations",
            headers: ['Authorization': "Bearer ${accessToken}", 'requestContentType': "JSON", 'Accept': "application/json;v=1.0"]
            //, query: [provider: 'OSA']
    )
            { resp2, reader3 ->
                resultsReady = reader3['violations']
                file.append("\r\nPolicy Violations\n");
                cnt = 0
                for (item in resultsReady) {
                    for (i = 0; i < item.size(); i++)
                    {
                        println(item[i].get('name'))
                        println(item[i].get('source'))
                        println(item[i].get('ruleName'))
                        println(item[i].get('severity'))
                        println(item[i].get('type'))
                        file.append("\n" + item)
                    }

                }
            }
} catch (groovyx.net.http.HttpResponseException ex) {
    println("Cannot connect to " + host)
    System.exit(9)

} catch (java.net.ConnectException ex) {
    println("Cannot connect to " + host)
    System.exit(10)
}


// *****************************************************************
// ***   Retrieve list of Vulnerabilites for specific scan       ***
// *****************************************************************

println("\n Retrieve vulnerabilities for " + scanIDval + " " + resultsReady )

    println("\n Retrieve vulnerabilities for " + scanIDval + " " + resultsReady )
    try{
        site.get(path: '/cxrestapi/osa/vulnerabilities',
                headers: ['Authorization': "Bearer ${accessToken}", 'requestContentType': "JSON"],
                query: [scanId: scanIDval])
                { resp2, json ->
                    def String rVal = ""

                    rVal << json

                    // lets split the lines up for readability
                    for (item in json)
                    {
                        String thisItem = item
                        item2 =	thisItem.replaceAll("\\r?\\n", ' ')
                        //println (rVal)
                    }

                    def json2 = new groovy.json.JsonBuilder()
                    json2.call(json)

                    file.append("\r\nvulnerabilities\n" + json2.toPrettyString());


                    println("\n" + json)
                }
    } catch (groovyx.net.http.HttpResponseException ex) {
        println("Cannot connect to " + host)
        System.exit(7)

    } catch (java.net.ConnectException ex) {
        println("Cannot connect to " + host)
        System.exit(8)
    }



// **********************************************************************
// ***   Retrieve list of Risky Licenses for specific project scan    ***
// **********************************************************************
try{
    println("\n Retrieve licenses for " + scanIDval)
    site.get(path: '/cxrestapi/osa/licenses',
            headers: ['Authorization': "Bearer ${accessToken}", 'Accept: application/json':"v=1.0/2.0"],
            query: [scanId: scanIDval])
            { resp3, reader4 ->
                // lets split the lines up for readability
                for (item in reader4)
                {
                    String thisItem = item
                    item2 =	thisItem.replaceAll("\\r?\\n", ' ')

                }

                def json4 = new groovy.json.JsonBuilder()
                json4.call(reader4)
                file.append("\r\n licenses\n" + json4.toPrettyString());
            }




} catch (groovyx.net.http.HttpResponseException ex) {
    println("Cannot connect to " + host)
    System.exit(11)

} catch (java.net.ConnectException ex) {
    println("Cannot connect to " + host)
    System.exit(12)
}

def encodeZipFile( Object data ) throws UnsupportedEncodingException {
    if ( data instanceof File ) {
        def entity = new FileEntity( (File) data, "application/x-zip-compressed" );
        entity.setContentType( "application/x-zip-compressed" );
        println("Encoding to application/x-zip-compressed")
        return entity
    } else {
        throw new IllegalArgumentException(
                "Don't know how to encode ${data.class.name} as a zip file" );
    }
}


def submitScan(host, projId2Scan, accessToken )
{

// *************************************************
// ***           submit scan       ***
// *************************************************
    def scanIDval = 0
    try {
        // File zip = new File("C:\\Users\\andrewt\\OneDrive - Checkmarx\\Projects\\OSA\\lib.zip")
        File zip = new File("v:\\temp.zip")
        println("file exists " + zip.exists())

        def http = new HTTPBuilder("${host}/cxrestapi/osa/scans")

        http.encoder.'application/x-zip-compressed' = this.&encodeZipFile

        Map<String,String> map=new HashMap<String,String>();
        map.put("Authorization","Bearer ${accessToken}");
        http.setHeaders(map)

        http.request(Method.POST) { req ->
            requestContentType: "multipart/form-data"
            MultipartEntity multiPartContent = new MultipartEntity(HttpMultipartMode.BROWSER_COMPATIBLE)

            cxOrigin: "Portal"

            multiPartContent.addPart("projectID", new StringBody(projId2Scan.toString()))
            multiPartContent.addPart("zippedSource", new InputStreamBody(new FileInputStream(zip), "application/x-zip-compressed", "lib.zip"))

            req.setEntity(multiPartContent)

            response.success = { resp, reader ->

                if (resp.statusLine.statusCode == 202) {

                    // response handling
                    scanIDval = reader['scanId']
                }
                println("\n" + resp.statusLine.statusCode)
            }


        }
    } catch (groovyx.net.http.HttpResponseException ex) {
        println("" + ex.getMessage() + " " + ex.getStatusCode())


        System.exit(13)

    }

    println("Returning scanid " + scanIDval)
    return scanIDval;
}


// *************************************************
// ***           calculate Policy      ***
// *************************************************
def calculatePolicy(host, projId2Scan, accessToken )
{
    println("${host}/cxarm/policymanager/projects/${projId2Scan}/violationscalculation")
    rVal = 0
    try {
        def http = new HTTPBuilder("${host}/cxarm/policymanager/projects/${projId2Scan}/violationscalculation")

        Map<String,String> map=new HashMap<String,String>();
        map.put("Authorization","Bearer ${accessToken}");
        http.setHeaders(map)

        http.request(Method.POST) { req ->
            response.success = { resp, reader ->
                rVal = resp.statusLine.statusCode
                if (resp.statusLine.statusCode == 202) {

                    // response handling
                    scanIDval = reader['scanId']
                }
                println("\n" + resp.statusLine.statusCode)
            }
        }
    } catch (groovyx.net.http.HttpResponseException ex) {
        println("" + ex.getMessage() + " " + ex.getStatusCode())


        System.exit(14)

    }
    return rVal
}