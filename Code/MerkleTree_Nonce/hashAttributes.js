import process from 'process';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const util = require('util');
// const keccak256 = require('keccak256')
const createKeccakHash = require('keccak')

let crypto;
var config =require('../config.json');

 try {
 	crypto = require('crypto');
 	let h = await crypto.getHashes();
 	console.log("Available hash algorithms..");
 	console.log(h);
 }catch (err){
 	console.log('crypto support is disabled');
 	process.exit();
 }


const generateKey = util.promisify(crypto.generateKey);


/*export const hashAttributes = async (attribute, key = undefined, keylength = config.hash.keylength, type =config.hash.C) => {
	if(!key){
       key = await generateKey('hmac',{length:keylength});
	   key = key.export().toString('hex');
	}

	//const keccak256 = require('js-sha3').keccak256;
	// const hmac=keccak256.hmac(type,key,"hex");
	console.log("prova 1: " + keccak256(attribute));
	console.log("prova 2: " + keccak256(attribute));
	//console.log(hmac)
	const result =0;
	/!*hmac.update(attribute);
	const result = await hmac.digest('hex');
	console.log(result)*!/

	/!*console.log(type)
	const hmac = await crypto.createHmac(type,key);
   hmac.update(attribute);
   	const result = await hmac.digest('hex');
	   console.log(result)*!/
    return { nonce: key, res: result};
}*/
export const hashAttributes = async (attribute, key = undefined, keylength = config.hash.keylength, type =config.hash.C) => {
	const {createHash} = await import('node:crypto');
	console.log("Algoritmo è: " + type);
	if(!key){
		key = await generateKey('hmac',{length:keylength});
		key = key.export().toString('hex');
	}

	/* Utilizzo HMAC-Keccak256 della libreria https://github.com/cryptocoinjs/keccak */
	// const result= createKeccakHash('keccak256').update(attribute+key).digest('hex')
	/* fine utilizzo HMAC-Keccak256 */

	/* Utilizzo crypto per SHA3-256 */
	console.log("sha3-256 function HLeaves")
	let hash = createHash("sha3-256");
	console.log("hash " + hash)
	hash.update(attribute+key)
	const result=hash.digest('hex')
    /* fine utilizzo SHA3-256*/

	// const result = keccak256(Buffer.from(attribute+key))
	// const hmac = await crypto.createHmac(keccak256(Buffer.from(attribute),Buffer.from(key)));
	// hmac.update(attribute);
	// const result = await hmac.digest('hex');
	console.log(result)
	return { nonce: key, res: result};
}

hashAttributes("ciao",undefined)
hashAttributes("ciao",undefined)