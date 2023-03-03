# Installation instructions from source

Clone the FAME repository:
```
$ git clone https://github.com/zRapha/FAME
```
Create a virtual environment & activate it:
```
$ python3.7 -m venv fame-env
$ source fame-env/bin/activate
```
Update pip if needed (pip~=20.0):
```
$ pip install --upgrade pip
```

Install required packages:
```
$ pip install -r requirements.txt
```
## Integrity test verification  
Per default the functionality stage is implemented using Cuckoo, an analysis environment that has an extensive documentation support: https://cuckoo.sh/docs/. Cuckoo provides dynamic analysis results, which can be useful to understand the adversarial examples generated. A local beta-test implementation is also provided for further extension.

## Malware classification   
Local classification models are implemented to perform detection using  pre-trained malware classifier, namely, LightGBM trained with both EMBER and SOREL datasets. For those interested in more classifiers, we provide the option of using aggregators via REST APIs in order to assess adversarial examples against a wider range of commercial engines.

## Dataset
There are several public repositories containing labeled malicious files to test the environment. Once the data is acquired, it should be placed under samples/malware_set/.

## Further environment isolation [optional]
Even though the manipulations do not require to run any file, the integrity verification stage does. Hence, it is  recommended to use isolated sandboxes and simulated services. One option is to use _inetsim_.

Disable interface:
```
$ sudo ifconfig <network_int> down
```

Run inetsim:
```
$ cd /etc/default/inetsim-1.2.8/
$ sudo ./inetsim
```

Note that automatically retrieving the detection rate for a malware file from an online aggregator will no longer be functional unless adjusted manually.

## How to run FAME

### 1. Activate Cuckoo Python venv:
```
$ source ~/Documents/venvs/cuckoo-env/bin/activate
```

> If integrity verification is implemented proceed with _2_, otherwise jump to _5_. 

### 2. Run Mongo DB for webserver:
```
$ sudo service mongod start
```

### 3. Run webserver [optional]:
```
$ cd ~/.cuckoo/
$ cuckoo web
``` 

### 4. Run API & Cuckoo sandbox:
```
$ cuckoo api
$ cuckoo
```

### 5. Adjust configuration and initial parameters:
```
$ vi config.ini
```

### 6. Run FAME:
```
$ ./main.py aimed
```

## Segmentation fault 
We have observed that injecting some combinations of perturbations to specific PE files raise segmentation fault 
issues. Due to the nature of memory violations and the occurrence of this issue (in our experiments less than 0.02% of 
the cases) we recommend either adjusting the transformations' sequence to a different combination or trying a new example. 
Sometimes not patching the original import table, setting `builder.patch_imports(False)`, may also help prevent this issue. 
A workaround is curating the dataset by identifying the PE file and excluding it from the process.


