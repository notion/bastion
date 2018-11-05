Bastion
=======

The Trove SSH Bastion handles all authentication into remote Trove resources. The bastion supports either standalone use (single instance) or clustered mode using Google Cloud. Clustered mode takes advantage of [Google TCP/HTTPS Loadbalancers](https://cloud.google.com/load-balancing/), [Autoscaled Instance Groups](https://cloud.google.com/compute/docs/autoscaler/), and [Identity Aware Proxy](https://cloud.google.com/iap/). It supports storing information either in MySQL (for clustered mode, this is necessary) or SQLite, and storing compressed SSH sessions in Google Cloud Storage. 

## How it works
The Bastion works by acting as a SSH Certificate Authority and uses these certificates for authorization. Certificates only live for a configurable length of time, and authorization for a user can be disabled instantly or certificates can be regenerated, removing the authenticity of old certificates. Server authorization is provided on a per-user basis by verifying the user has authorization on a connecting host/hostname basis. All actions are logged, and sessions can be joined through the web interface. Sessions are stored in the familiar [Asciicast V2](https://github.com/asciinema/asciinema/blob/develop/doc/asciicast-v2.md) format. Sessions can be disconnected mid-layer through the bastion. This is supposed to serve as a single point of access into one's private cloud, rather than the typical VPN based model. All SSH actions (to the best of my knowledge) are implemented by this proxy.

## Deployment steps
Internally, we use Chef to deploy the bastion. Most of this is taken care of automatically. There is also a Dockerfile (and subsequent image) bundled with this repo that can also be used for deployment and as a binary builder. 

1. Download this repository
    - ```git clone https://github.com/notion/bastion```
2. Run a docker build
    - ```docker build -t bastion .```
3. Start the bastion
    - ```docker run -it --rm -p 5222:5222 -p 8080:8080 bastion```

## Configuration
The `config.example.yml` file explains all of the configuration options available for this application. There is also a `credentials.json` file required for handling GCS credentials.