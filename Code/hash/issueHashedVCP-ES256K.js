import {Resolver} from 'did-resolver'
import getResolver from 'ethr-did-resolver'
import { EthrDID } from 'ethr-did'
import { ethers } from 'ethers' 
import { computePublicKey } from '@ethersproject/signing-key'
import { createVerifiableCredentialJwt, createVerifiablePresentationJwt, verifyPresentation,  verifyCredential, normalizeCredential, validateCredentialPayload } from 'did-jwt-vc';
//import { ES256KSigner } from 'did-jwt'
// import pkg, { verifyCredential, normalizeCredential, validateCredentialPayload } from 'did-jwt-vc';
// const { createVerifiableCredentialJwt, createVerifiablePresentationJwt, verifyPresentation } = pkg;
import bip39 from 'bip39'
import { createRequire } from 'module';
import {hashAttributes} from './hashAttributes.js'
import {verifyAttributes} from './verifyAttributes.js'

const require = createRequire(import.meta.url);
var config =require('../config.json');
const hdkey = require('ethereumjs-wallet/hdkey')
const didJWT = require('did-jwt');
//import wallet from 'ethereumjs-wallet'

const { performance } = require('perf_hooks'); // performance suite for time measurement


const mnemonic = 'family dress industry stage bike shrimp replace design author amateur reopen script';
const disclosure=new Map()
//function that retrieves private keys of Truffle accounts
// return value : Promise
const getTrufflePrivateKey = (mnemonic, index) => {
	if (index < 0 || index > 9) throw new Error('please provide correct truffle account index')
	return bip39.mnemonicToSeed(mnemonic).then(seed => {
		const hdk = hdkey.fromMasterSeed(seed);
		const addr_node = hdk.derivePath(`m/44'/60'/0'/0/${index}`); //m/44'/60'/0'/0/0 is derivation path for the first account. m/44'/60'/0'/0/1 is the derivation path for the second account and so on
		//const addr = addr_node.getWallet().getAddressString(); //check that this is the same with the address that ganache list for the first account to make sure the derivation is correct
		const privKey = addr_node.getWallet().getPrivateKey();
		return privKey;
	}).catch(error => console.log('getTrufflePrivateKey ERROR : ' + error));
}

async function createVCPayload(user,nClaims) {
	const VCPayload={};
	//VCPayload['sub']=user.did;
    //VCPayload['nbf']=626105238;
    VCPayload['vc']= {
			'@context': ['https://www.w3.org/2018/credentials/v1'],
			type: ['VerifiableCredential'],
			credentialSubject: {}
		};
	for (let i = 0; i < nClaims; i++) {
		var attrName="attrName"+i;
		var attrValue="attrValue"+i;
  		const hashedAttr = await hashAttributes(attrValue,undefined,undefined,undefined);
  		disclosure.set(attrName,{path : [attrName],clearValue : attrValue,nonce : hashedAttr.nonce});
  		//disclosure[attrName]={
		//path : [attrName],
		//clearValue : attrValue,
		//nonce : hashedAttr.nonce}
  		VCPayload['vc']['credentialSubject'][attrName] = hashedAttr.res;
	} 
	return VCPayload;
}

function createVPPayload(vc,nClaims) {
	const VCPayload={};
	//VCPayload['sub']=user.did;
    //VCPayload['nbf']=626105238;
    VCPayload['vp']= {
			'@context': ['https://www.w3.org/2018/credentials/v1'],
			type: ['VerifiablePresentation'],
			verifiableCredential: [vc]
		};
	VCPayload['vp']['attributes']=[];
	if (nClaims==disclosure.size) {
		disclosure.forEach (function(value, key){
			VCPayload['vp']['attributes'].push(value);
		});	
	}else{
		let keys=Array.from(disclosure.keys());
		for (let i = 0; i < nClaims; i++) {
			let attN=keys[Math.floor(Math.random()*keys.length)];
			VCPayload['vp']['attributes'].push(disclosure[attN]);
		}
	}
	return VCPayload;
}

//setup the provider 
console.log('Connecting to provider...');
const Web3HttpProvider = require('web3-providers-http')
// ...
const web3provider = new Web3HttpProvider('http://localhost:9545')
const provider = new ethers.providers.Web3Provider(web3provider)
//const provider = new ethers.providers.JsonRpcProvider('http://localhost:9545');

// get accounts provided by Truffle, with respective private keys


console.log('Connected to the provider');
//contract address of the registry
const RegAddress = '0x1482aDFDC2A33983EE69F9F8e4F852c467688Ea0';

//function where the creation of an identity will be tested
const test = async (accounts) => {
	// create DID of the interacting subjects
	const uni = await createDid(RegAddress, accounts[0], 0);
	
	//creating holder and verifier DIDs
	const PaoloMori = await createDid(RegAddress, accounts[1], 1);
	

	// create the DID resolver 
	const ethrDidResolver = getResolver.getResolver(
		{
			rpcUrl: 'http://localhost:7545',
			registry: RegAddress,
			chainId: '0x539',
			provider
		}
	);
	const didResolver = new Resolver(ethrDidResolver);

	const options = {		
		header: {
			"typ": "JWT",
			"alg": "ES256K"
		},
	};

	// create VC issued by university to Paolo Mori
	let vcCreationTimes=[];

	
	for (let i = 1; i < 11; i++) {
		let res=0.0;
		let jwtP;
		let jwtSize=0;
		disclosure.clear();
		console.log(Math.pow(2, i));
		let nCl=Math.pow(2, i);
		const VCPayload = await createVCPayload(PaoloMori,Math.pow(2, i));
		const jwt = await createVerifiableCredentialJwt(VCPayload, uni, options);
		for (let j = 0; j <config.hash.iterations; j++) {
			let start = performance.now();
				const VPPayload=createVPPayload(jwt,nCl);
				 jwtP=await createVerifiablePresentationJwt(VPPayload,PaoloMori,options);
			let end = performance.now();
			const createVCtime = (end-start);
  		    //const signedVC = await createVCPerformance(VCPayload, uni, options);
  		    res = res + createVCtime;
  		    jwtSize = jwtSize + memorySizeOf(jwtP);
  		}
  		vcCreationTimes.push([res/config.hash.iterations,jwtSize/config.hash.iterations]);
  	}
	
	console.log(vcCreationTimes);


	const fs = require('fs')
	const file = fs.createWriteStream('issueHashedVCP-ES256K.txt');

	file.on('error', (err) => {
		if(err) throw console.error(err)
	});
	let k=1
	vcCreationTimes.forEach((v) => {
		let NumAttr= Math.pow(2,k);
		k++;
		file.write( NumAttr.toString() +' '+v.join(' ') + '\n');

	});

	file.end();
	//vcCreationTimes.push(signedVC.res);
	//console.log(signedVC.time);


	//let start = performance.now();
	//const verificationResponse = await didJWT.verifyJWT(signedVC.res, {resolver:didResolver});
	//let end = performance.now();
	
	//const verifyVCtime = "Verify VC took " + (end-start) + "ms";
	//console.log(verificationResponse);
	//console.log(normalizeCredential.toString());
	//start = performance.now();
	//const normalizedVC=normalizeCredential(verificationResponse.jwt,true);
	//validateCredentialPayload(normalizedVC);
	//end = performance.now();
	//const validateVCtime = "Validate VC took " + (end-start) + "ms";
	
	
	//console.log(verificationResponse);
	//console.log(normalizedVC);
	//console.log(signedVC.time);
	//console.log(verifyVCtime);
	//console.log(validateVCtime);

	
	//const verifyVC = verifyCredentialPerformance(signedVC.res,didResolver);
	//console.log(verifyVC.res);
	//console.log(verifyVC.time);
}

//function to create and return the object used to manage a DID
const createDid = async (RegAddress, accountAddress, index, chainId = '0x539') => {
	return getTrufflePrivateKey(mnemonic, index)
		.then(privateKey => {
			const publicKey = computePublicKey(privateKey, true);
			const uncompressedPublicKey = computePublicKey(privateKey, false);
			console.log(publicKey);
			console.log(uncompressedPublicKey);
			console.log(privateKey);
			const identifier = `did:ethr:${chainId}:${publicKey}`;
			const signer = provider.getSigner(index);
			//const signJ=didJWT.SimpleSigner(privateKey);
		   //const signJ=didJWT.EllipticSigner(privateKey);
		  
		   //const signJ=didJWT.EdDSASigner(privateKey);
		   const signJ=didJWT.ES256KSigner(privateKey,false);
			const conf = {
				//txSigner: signer,
				//privateKey : privateKey,
				signer: signJ,
				identifier: identifier,
				registry: RegAddress,
				chainNameOrId: chainId,
				provider
			};
			return new EthrDID(conf);
		})
}



const createVCPerformance = async (payload, did, options) => {
	let start = performance.now();
	const jwt = await createVerifiableCredentialJwt(payload, did, options);
	let end = performance.now();
	const createVCtime = (end-start);
	return {res : jwt, time : createVCtime};
}
const createVPPerformance =  async (payload, did, options) => {
	let start = performance.now();
	const jwt = await createVerifiablePresentationJwt(payload, did, options);
	let end = performance.now();
	const createVPtime = "Create VP took " + (end-start) + "ms"
	return {res : jwt, time : createVPtime} ;
}

const verifyPresentationPerformance = async (jwt, resolver) => {
	let start = performance.now();
	const result = await verifyPresentation(jwt, resolver);
	let end = performance.now();
	const verifyVPtime = "Verify VP took " + (end-start) + "ms"
	return {res : result, time : verifyVPtime};
}

const verifyCredentialPerformance = async (jwt, didResolver) => {
	let start = performance.now();
	//const result = await verifyCredential(jwt, resolver);
	let verificationResponse = await didJWT.verifyJWT(jwt,{resolver:didResolver});
	let end = performance.now();
	const verifyVCtime = "Verify VC took " + (end-start) + "ms"
	return {res : verificationResponse, time : verifyVCtime};
}

//actual function that starts executing and this will invoke all the other pieces of code

provider.listAccounts().then((accounts) => {
	test(accounts).catch(error => console.log(error));
	//getTrufflePrivateKey(mnemonic,0).then(res => console.log(res.toString('hex')));
});


function memorySizeOf(obj) {
    var bytes = 0;

    function sizeOf(obj) {
        if(obj !== null && obj !== undefined) {
            switch(typeof obj) {
            case 'number':
                bytes += 8;
                break;
            case 'string':
                bytes += obj.length * 2;
                break;
            case 'boolean':
                bytes += 4;
                break;
            case 'object':
                var objClass = Object.prototype.toString.call(obj).slice(8, -1);
                if(objClass === 'Object' || objClass === 'Array') {
                    for(var key in obj) {
                        if(!obj.hasOwnProperty(key)) continue;
                        sizeOf(obj[key]);
                    }
                } else bytes += obj.toString().length * 2;
                break;
            }
        }
        return bytes;
    };

    function formatByteSize(bytes) {
        if(bytes < 1024) return bytes + " bytes";
        else if(bytes < 1048576) return(bytes / 1024).toFixed(3) + " KiB";
        else if(bytes < 1073741824) return(bytes / 1048576).toFixed(3) + " MiB";
        else return(bytes / 1073741824).toFixed(3) + " GiB";
    };

    return sizeOf(obj);
};
