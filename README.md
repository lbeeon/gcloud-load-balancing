# Google Cloud Platform Load Balance api wrapper
A partial wrapper of [api/compute](https://google.golang.org/api/compute/v1)  

### How to use
```
import lbt "github.com/lbeeon/gcp-loadbalance"

// keyPath ex: ./credential/credential.json
tools := lbt.NewLoadBalanceTools(projectID string)
backendServ, err := tools.GetBackendService("service_name")

// polling result automatically
op, err := tools.InsertCertificate("new_cert", []string{"https://www.googleapis.com/compute/v1/projects/xxxxxxxx-xxxxxx-xxxxx/global/sslCertificates/xxxxxxxx"})
```

### Method List

    GetBackendService func(name string) (*compute.BackendService, error)

    GetUrlMap func(name string)(*compute.UrlMap, error)

    GetTargetHttpProxy func(name string)(*compute.TargetHttpProxy, error)

    GetTargetHttpsProxy func(name string)(*compute.TargetHttpsProxy, error)

    GetGlobalAddress func(name string) (*compute.Address, error)

    GetForwardRule func(name string) (*compute.ForwardingRule, error)

    GetSslCertificate func(name string)(*compute.SslCertificate, error)

    InsertUrlMap func(name string, defaultService string)(*compute.Operation, error)

    InsertTargetHttpProxy func(name string, urlMap string)(*compute.Operation, error)

    InsertTargetHttpsProxy func(name string, urlMap string, sslCert []string)(*compute.Operation, error)

    InsertTcpGlobalForwardRule func(name string, ipAddress string, targetProxy string, portRange string) (*compute.Operation, error)

    InsertGlobalAddress func(name string)(*compute.Operation, error)

    InsertCertificate func (name string, certificate string, privateKey string) (*compute.Operation, error)

    SetTargetHttpsProxySslCert func (name string, sslCert []string)(*compute.Operation, error)

### How to create load balancer programmatically

To create a global address with certificate and add into the load balance url-map is quite complex. It takes a few of google cloud apis to accomplish the task. Below are the steps of the api calls.  

1. Backend service

    The Backend Service would be create by "someone". In this case it would be a static const.

2. Url Map  

    The functional of the "Url Map" is toward the list of the "Frontend" to the specific backend service.

    If you want to create a whole new "Url Map" then you'll need a backend service as parameter.

    In this case it would be a static const.

3. Target proxy (http/https)  

    The Target Proxy is the bridge between the "Url Map" and "Global Address". Once it been connected, the load balance would add a list in the "Frontend" category.

    In the case you need to create a new Target Proxy, which towards to a "Url Map". The "Url Map" is towards to a group of Backend Service.  

    To create a http target proxy you'll need a "Url Map".  
    (https proxy needs ssl certificate see below)

4. Global address  

   The Global Address is the external ip address. With the ip, people can touch the backend service from the world wide web.

   In this case you need to create a new Global Address while the certain ip has been attached more than 50 domains.

   To create a Global Address, all you need is a "Name"

5. Forwarding rule (http/https)  

    The Forwarding rule integrated all the resources including "Target Proxy", "Global Address" and "Port Range". After the Forwarding Rule created, you'll see a new record in the load balance.

ps: Https target proxy needs certificate, follow below steps create and upload an certificate license.

1. Generate the private key and certificate with "Let's Encrypt" (lego).

2. Upload the private key and certificate to google cloud.

#### Update SSL Certificate

All the resources of above, and only the Target Proxy is related.
