export const decryptQr = (cipher) => {
	console.log('Received: ', cipher);
	try {
		const decoded = atob(cipher);
		return decoded.startsWith('test_key:') ? decoded.slice('test_key:'.length) : decoded;
	} catch {
		return ''; // invalid base64
	}
};
