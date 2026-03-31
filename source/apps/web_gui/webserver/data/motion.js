var csiObject;
var currentCSIFileName;
var intervalId;
const motionTypes = ['Move Finger', 'Move Hands', 'Walk', 'Jump'];
function drawSamples(data, index) {
   
	document.getElementById('UberVariance').innerHTML = Math.trunc(data.Devices[index]['UberVariance']); 
	var samples = data.Devices[index]['Magnitude'].length;
	if (samples == 0) {
		return;
	}

	let resData = [];
	var resLayout = {
        title: 'Gestures & Detection',
    };
    let algoElem = {
    	type: 'scatter',
        x: [],
        y: [],
        name: 'Detection',
    };

	for (let i = 0; i < samples; i++) {
		algoElem.x.push(i);
		algoElem.y.push(data.Devices[index]['AlgorithmResult'][i][0]);

		var peak_variance_percent = 0;
		if (data.Devices[index]['AlgorithmResult'][i][0] === 1) {
			peak_variance_percent = Math.trunc((data.Devices[index]['AlgorithmResult'][i][1]*100)/data.Devices[index]['UberVariance']);
		}
			
		document.getElementById('PeakDeviationPercent').innerHTML = peak_variance_percent; 
	}

	resData.push(algoElem);

    let gestureElem = {
    	type: 'scatter',
        x: [],
        y: [],
        name: 'Gesture',
    };
	for (let i = 0; i < samples; i++) {
		gestureElem.x.push(i);
		gestureElem.y.push(data.Devices[index]['Gestures'][i]);
	}

	resData.push(gestureElem);
		
	Plotly.newPlot('AlgorithmResult', resData, resLayout);
	

	let receivers = data.Devices[index]['Magnitude'][0].length;

	let heatMapData = [];
	var heatMapElem = {
    	z: [],
    	type: 'heatmap'
  	};

	var algorithmSamples = parseInt(document.getElementById('AlgorithmSamples').value, 10);

	if ((samples%algorithmSamples) === 0) {
			
		for (let i = 0; i < samples/algorithmSamples; i++) {	
			heatMapElem.z[i] = [];
			for (let j = i*algorithmSamples; j < algorithmSamples*(i + 1); j++) {
				heatMapElem.z[i].push(data.Devices[index]['Variance'][j][0]);		
			}
				
		}
	
		heatMapData.push(heatMapElem);
		Plotly.newPlot('HeatMap', heatMapData);
	}


	for (let i = 0; i < receivers; i++) {
	
		let antennaDiv = document.getElementById('Antenna' + (i + 1));

		let chartData = [];
		var chart_title = sprintf("%s:Antenna %d", data.Devices[index].MAC, i + 1);

		var layout = {
			grid: {rows: 1, columns: 4, pattern: 'independent'},
			title: chart_title,
		};
		let magElem = {
           		type: 'scatter',
                x: [],
                y: [],
				name: 'Magnitude',
    	};

		for (let j = 0; j < samples; j++) {
			magElem.x.push(j);
			magElem.y.push(data.Devices[index]['Magnitude'][j][i]);
		}
		
		chartData.push(magElem);

		let meanElem = {
           		type: 'scatter',
                x: [],
                y: [],
				name: 'Mean',
    	};
		for (let j = 0; j < samples; j++) {
			meanElem.x.push(j);
			meanElem.y.push(data.Devices[index]['Mean'][j][i]);
		}
		
		chartData.push(meanElem);
		
		let varianceElem = {
           		type: 'scatter',
                x: [],
                y: [],
				xaxis: 'x2',
  				yaxis: 'y2',
				name: 'Variance',
    	};

		for (let j = 0; j < samples; j++) {
			varianceElem.x.push(j);
			varianceElem.y.push(data.Devices[index]['Variance'][j][i]);
		}
		
		chartData.push(varianceElem);
		
		let kurtosisElem = {
           		type: 'scatter',
                x: [],
                y: [],
				xaxis: 'x3',
  				yaxis: 'y3',
				name: 'Kurtosis',
    	};

		for (let j = 0; j < samples; j++) {
			kurtosisElem.x.push(j);
			kurtosisElem.y.push(data.Devices[index]['Kurtosis'][j][i]);
		}
		
		chartData.push(kurtosisElem);
		
		let mfilterElem = {
           		type: 'scatter',
                x: [],
                y: [],
				xaxis: 'x4',
  				yaxis: 'y4',
				name: 'Mfilter',
    	};

		for (let j = 0; j < samples; j++) {
			mfilterElem.x.push(j);
			mfilterElem.y.push(data.Devices[index]['Mfilter'][j][i]);
		}
		
		chartData.push(mfilterElem);
		
		Plotly.newPlot(antennaDiv, chartData, layout);
	}
		
}

function renderMotionChart(data) {
	for (let i = 0; i < data.Devices.length; i++) {
		//drawSamples(data, i);
	}
	drawSamples(data, 0);
}

export async function abortHandler(event) {
    try {
        // Send the data using fetch with the POST method
        const response = await fetch('/abort-csi', {
            method: 'POST',
        });

        // Check if the request was successful
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const contentType = await response.headers.get("Content-Type");
        if (contentType === 'application/json') {
            const result = await response.json();
            if (result.Status === 'Event Pushed') {
				clearInterval(intervalId); // Stops the recurring interval
				document.getElementById('Analyze').disabled = false;
				document.getElementById('Abort').disabled = true;
				document.getElementById('Save').disabled = false;
			}
		}

    } catch (error) {
        console.error('Error:', error);
    }

}

export async function analyzeHandler(event) {

    const formData = {
        CSI: JSON.stringify(csiObject['CSI']),
		Start: document.getElementById('StartFrameRange').value, 
		End: document.getElementById('EndFrameRange').value, 
        Reporting: document.getElementById("Reporting").value,
        AlgorithmParameters: {
			AlgorithmSamples: document.getElementById("AlgorithmSamples").value,
			VarianceThreshold: {
				Value: document.getElementById("VarianceThreshold").value,
				Override: document.getElementById('OverrideVarianceThreshold').checked,
			},
			ConsecutiveSamples: document.getElementById("ConsecutiveSamples").value,
			AntennaConsiderations: document.getElementById("AntennaConsiderations").value,
		}
    };

    const jsonData = JSON.stringify(formData);
		
	var timeoutVal = (parseInt(document.getElementById('EndFrameRange').value, 10) - parseInt(document.getElementById('StartFrameRange').value, 10)) * 100;
	var countDownDate = new Date();
	countDownDate.setTime(countDownDate.getTime() + timeoutVal);

    try {
        const response = await fetch('/analyze-csi', {
            method: 'POST',
             headers: {
				'Content-Type': 'application/json',
                'Content-Length': jsonData.length,
             },
             body: jsonData,
        });

        // Check if the request was successful
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
				

        const contentType = await response.headers.get("Content-Type");
        if (contentType === 'application/json') {
            const result = await response.json();
            if (result.Status === 'Event Pushed') {
                // Execute fetch every Reporting Time
                intervalId = setInterval(fetchDataToRender, document.getElementById("Reporting").value, countDownDate);
				document.getElementById('Analyze').disabled = true;
				document.getElementById('Abort').disabled = false;
				document.getElementById('Save').disabled = true;
					
                // Stop the interval after analysis duration
                setTimeout(() => {
                   	clearInterval(intervalId); // Stops the recurring interval
                   	//console.log('Fetch cleared. Function will no longer execute.');
					document.getElementById('Analyze').disabled = false;
					document.getElementById('Abort').disabled = true;
					document.getElementById('Save').disabled = false;
                }, timeoutVal);
            }
        }


    } catch (error) {
        // Handle errors (e.g., network issues, server errors)
        console.error('Error:', error);
    }
}

function createTree(jsonObj, elem) {
	var entries = Object.entries(jsonObj);
	if (entries.length == 0) {
		return;
	}
		
	for (const [key, value] of entries) {
		const newLI = document.createElement('li');
		elem.appendChild(newLI);

		if ((typeof value === "object") || (typeof value === "array")) {
			const newSpan = document.createElement('span');
			newSpan.classList.add('caret');
			newSpan.innerHTML = `${key}`
			newLI.appendChild(newSpan);
	
			const newUL = document.createElement('ul');
			newUL.classList.add('nested');
			newLI.appendChild(newUL);

			createTree(value, newUL);
		} else {
			const memberLI = document.createElement('li');
			elem.appendChild(memberLI);
			memberLI.innerHTML = `${key}: ${value}`;
			memberLI.style.color = "blue";
		}
	}
}

export function fileChangeHandler(event) {
    const file = event.target.files[0];
    if (!file) {
        return;
    }

	currentCSIFileName = file.name;
	fetchCSIFile(currentCSIFileName);

}

async function fetchCSIFile(filename) {
    try {
        const response = await fetch('http://localhost:8081/raw_data/' + filename);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        csiObject = await response.json();
        document.getElementById('EndFrameRange').max = csiObject['CSI']['SoundingDevices'][0].length;
        document.getElementById('EndFrameRange').value = csiObject['CSI']['SoundingDevices'][0].length;
        document.getElementById('EndFrameSpan').innerHTML = csiObject['CSI']['SoundingDevices'][0].length;
        document.getElementById('StartFrameRange').max = csiObject['CSI']['SoundingDevices'][0].length;
        document.getElementById('StartFrameRange').value = 0;
        document.getElementById('StartFrameSpan').innerHTML = 0;
        
        // Check if the csiTree exists if not create one
        var newUL = document.getElementById("csiTree");
        if (newUL) {
            const parentElement = newUL.parentNode;

            if (parentElement) {
                parentElement.removeChild(newUL);
            }
        }
        newUL = document.createElement('ul');

        newUL.id = 'csiTree';
        document.getElementById('CSIFileDisplay').appendChild(newUL);

        createTree(csiObject, newUL);

        var toggler = document.getElementsByClassName("caret");
        var i;

        for (i = 0; i < toggler.length; i++) {
            toggler[i].addEventListener("click", function() {
                this.parentElement.querySelector(".nested").classList.toggle("active");
                this.classList.toggle("caret-down");
            });
        }


        document.getElementById('Analyze').disabled = false;
        
    } catch (error) {
        console.error('Error fetching data:', error);
    }

}

export async function fetchDataToRender(countDownDate) {
    try {
        const response = await fetch('http://localhost:8081/motion.json');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json(); // Or response.text() for plain text
		document.getElementById('AnalysisTimeLeft').innerHTML = getCountDownText(countDownDate).text;
        renderMotionChart(data);

    } catch (error) {
        console.error('Error fetching data:', error);
    }
}


    
export function sliderInputHandler(event) {

	if (event.target.name === 'StartFrameRange') {
    	document.getElementById('StartFrameSpan').textContent = this.value;
	} else if (event.target.name === 'EndFrameRange') {
    	document.getElementById('EndFrameSpan').textContent = this.value;
    	document.getElementById('StartFrameRange').max = this.value;
	}
}

export function fileLoadHandler() {
	document.getElementById('Analyze').disabled = true;
	document.getElementById('Abort').disabled = true;
	document.getElementById('Save').disabled = true;
	document.getElementById('SavedCapture').checked = true;

	const savedCapture = document.createElement('input');
	savedCapture.setAttribute('type', 'file');
    savedCapture.setAttribute('id', 'CSI');
    savedCapture.setAttribute('name', 'CSI');
    savedCapture.setAttribute('accept', '.json');
    savedCapture.addEventListener('change', fileChangeHandler);

    document.getElementById('CaptureControls').appendChild(savedCapture);
}

export async function saveHandler() {
	try {
		var promises = [];
		var imgData = {
			file: "",
        	data: []
    	};
	
		for (let i = 0; i < 4; i++) {
			var elemName = sprintf('Antenna%d', i + 1);
			promises.push(Plotly.toImage(document.getElementById(elemName), {format: 'png', height: 300, width: 800}));
		}
	
		const resolutions = await Promise.all(promises);

		for (let i = 0; i < resolutions.length; i++) {
			imgData.data.push(resolutions.at(i));
		}

		imgData.file = currentCSIFileName.replace(/.json/g, "");
	
		const jsonData = JSON.stringify(imgData);
		//console.log(jsonData);

		try {
        	// Send the data using fetch with the POST method
        	const response = await fetch('/save-csi', {
            	method: 'POST',
             	headers: {
                	'Content-Type': 'application/json',
                	'Content-Length': jsonData.length,
             	},
             	body: jsonData,
        	});

        	// Check if the request was successful
        	if (!response.ok) {
            	throw new Error(`HTTP error! status: ${response.status}`);
        	}

        	const contentType = await response.headers.get("Content-Type");
        	if (contentType === 'application/json') {
            	const result = await response.json();
            	if (result.Status === 'Event Pushed') {
                	//console.log('Content Saved');
					document.getElementById('Save').disabled = true;
            	}
        	}

    	} catch (error) {
        	// Handle errors (e.g., network issues, server errors)
        	console.error('Error:', error);
    	}

	} catch (error) {
		console.log('Problem in converting to png file');
	}
}

export async function leftFileChangeHandler(event) {
    const file = event.target.files[0];
    if (!file) {
        return;
    }

    try {
        const response = await fetch('http://localhost:8081/saved/' + file.name);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.blob();
        const arrayBuffer = await data.arrayBuffer();
        
        const byteArray = new Uint8Array(arrayBuffer);
        const imgString = 'data:image/png;base64,' + byteArray.toBase64();

        document.getElementById('comparison-left').src = imgString;
    
    } catch (error) {
        console.error('Error fetching data:', error);
    }
		
}

export async function rightFileChangeHandler(event) {
    const file = event.target.files[0];
    if (!file) {
        return;
    }

    try {
        const response = await fetch('http://localhost:8081/saved/' + file.name);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.blob();
        const arrayBuffer = await data.arrayBuffer();
        
        const byteArray = new Uint8Array(arrayBuffer);
        const imgString = 'data:image/png;base64,' + byteArray.toBase64();

        document.getElementById('comparison-right').src = imgString;
    
    } catch (error) {
        console.error('Error fetching data:', error);
    }
}

export function clearHandler() {
	document.getElementById('LeftFile').value = null;	
	document.getElementById('RightFile').value = null;	
        
	document.getElementById('comparison-left').src = null;
	document.getElementById('comparison-right').src = null;
}

export function newCaptureHandler() {
	document.getElementById('NewCaptureParams').showModal();
	document.getElementById('StartNewCapture').disabled = true;
	document.getElementById('AbortNewCapture').disabled = true;
}

export function captureTypeHandler(value) {
	if (value === '1') {
		document.getElementById('Capture').remove();
		
		const savedCapture = document.createElement('input');
		savedCapture.setAttribute('type', 'file');
		savedCapture.setAttribute('id', 'CSI');
  		savedCapture.setAttribute('name', 'CSI');
  		savedCapture.setAttribute('accept', '.json');
		savedCapture.addEventListener('change', fileChangeHandler);

		document.getElementById('CaptureControls').appendChild(savedCapture);
	} else {
		document.getElementById('CSI').remove();
		document.getElementById('CaptureControls').appendChild(createButton('Capture', 'New Capture', 'button', true, newCaptureHandler));
	}
}

function createButton(id, label, class_name, enabled, listener) {
    const button = document.createElement('button');
		
	button.setAttribute('id', id);
	button.classList.add(class_name);
	button.textContent = label; 
	button.disabled = !enabled; 
		
	button.addEventListener('click', listener);

	return button;
}

function motionTypeCheckBoxChangeHandler(event) {
	var al_least_one_motion_type = false;

	for (let i = 0; i < motionTypes.length; i++) {
		if (document.getElementById(motionTypes[i].replace(/\s/g, '')).checked === true) {
			al_least_one_motion_type = true;
			break;
		}
	}

	if (al_least_one_motion_type === false) {
		document.getElementById('MotionStart').disabled = true;
	} else {
		document.getElementById('MotionStart').disabled = false;
	}
}

function createCheckbox(id, name, value, labelText, checked) {
    const label = document.createElement('label');
    label.htmlFor = id; // Associate the label with the input using the 'for' attribute

    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.id = id;
    checkbox.name = name;
    checkbox.value = value;
    
    checkbox.checked = checked;

    // Create a text node for the label text
    const textNode = document.createTextNode(labelText);

    // Append the checkbox and the text to the label
    label.appendChild(textNode);
    label.appendChild(checkbox);

	checkbox.addEventListener('change', motionTypeCheckBoxChangeHandler);

    // Return the complete label element containing the checkbox
    return label;
}

async function motionStartStopHandler(event) {
		
	var motionTypeInfo = {
		Descriptor: '',
		Action: true,
   	};
	
	if (event.target.id === 'MotionStart') {
		document.getElementById('MotionStart').disabled = true;
		document.getElementById('MotionStop').disabled = false;
	} else {
		document.getElementById('MotionStart').disabled = false;
		document.getElementById('MotionStop').disabled = true;
	}

	var motionTypeInfoArray = [];

	for (let i = 0; i < motionTypes.length; i++) {
		if (document.getElementById(motionTypes[i].replace(/\s/g, '')).checked === true) {
			motionTypeInfo.Descriptor = motionTypes[i].replace(/\s/g, '');
			motionTypeInfo.Action = document.getElementById('MotionStart').disabled;
			
			motionTypeInfoArray.push(motionTypeInfo);
		}
	}

	const jsonData = JSON.stringify(motionTypeInfoArray);

	for (let i = 0; i < motionTypes.length; i++) {
		document.getElementById(motionTypes[i].replace(/\s/g, '')).disabled = document.getElementById('MotionStart').disabled;
	}

	try {
		const response = await fetch('/motion-info-csi', {
        	method: 'POST',
            headers: {
            	'Content-Type': 'application/json',
            	'Content-Length': jsonData.length,
			},
            body: jsonData,
		});

		if (!response.ok) {
			throw new Error(`HTTP error! status: ${response.status}`);
		}

	} catch (error) {
		console.error('Error:', error);
	}
}

function getCountDownText(countDownDate)
{
    var now = new Date().getTime();
    var distance = countDownDate - now;

    var minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
    var seconds = Math.floor((distance % (1000 * 60)) / 1000);

	const text = minutes + "m " + seconds + "s";
	return { text: text, number: distance };
}

function addMotionControls(countDownDate) {
	const elements = [];

    var newP = document.createElement('p');
    newP.id = 'CaptureCountdown';
    document.getElementById('CaptureCountDownDiv').appendChild(newP);
    newP.innerHTML = getCountDownText(countDownDate).text;
	newP.style.fontSize = '40px';
	newP.style.textAlign = 'center';
	elements.push(newP);


	for (let i = 0; i < motionTypes.length; i++) {
		var newCheck;

		newCheck = createCheckbox(motionTypes[i].replace(/\s/g, ''), motionTypes[i], motionTypes[i].replace(/\s/g, ''), motionTypes[i], false);
    	document.getElementById('MotionTypesDiv').appendChild(newCheck);
		elements.push(newCheck);

	}

	document.getElementById(motionTypes[0].replace(/\s/g, '')).checked = true;

	var newButton;

	newButton = createButton('MotionStart', 'Motion Start', 'button', true, motionStartStopHandler);
	document.getElementById('MotionTypesButtonsDiv').appendChild(newButton);
	elements.push(newButton);

	newButton = createButton('MotionStop', 'Motion Stop', 'button', false, motionStartStopHandler);
	document.getElementById('MotionTypesButtonsDiv').appendChild(newButton);
	elements.push(newButton);

	return elements;
}

export async function startNewCaptureHandler() {
    const formData = {
        SoundingDevices: [],
		Duration: 18000, 
    };

	for (let i = 0; i < document.getElementById('SoundingDevices').options.length; i++) {
		if (document.getElementById('SoundingDevices').options[i].selected === true) {
			formData.SoundingDevices.push(document.getElementById('SoundingDevices').options[i].value);
		}
	}

	const timeoutVal = parseInt(document.getElementById('CaptureDuration').value, 10);
	formData.Duration = timeoutVal;

    const jsonData = JSON.stringify(formData);
		
    try {
        const response = await fetch(document.getElementById('GatewayURL').value + '/capture-csi', {
            method: 'POST',
             headers: {
				'Content-Type': 'application/json',
                'Content-Length': jsonData.length,
             },
             body: jsonData,
        });

        // Check if the request was successful
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
				
        const contentType = await response.headers.get("Content-Type");
        if (contentType === 'application/json') {
            const result = await response.json();
            if (result.Status === 'Event Pushed') {
				document.getElementById('StartNewCapture').disabled = true;
				document.getElementById('AbortNewCapture').disabled = false;

				var countDownDate = new Date();
				countDownDate.setTime(countDownDate.getTime() + timeoutVal);

				const elements = addMotionControls(countDownDate);
				
				var x = setInterval(function() {
					const countDown = getCountDownText(countDownDate);
  					document.getElementById('CaptureCountdown').innerHTML = countDown.text;
    
  					// If the count down is over, write some text 
  					if (countDown.number <= 0) {
    					clearInterval(x);
						for (let i = 0; i < elements.length; i++) {
							elements[i].remove();
						}
  					}
				}, 1000);	
				
                setTimeout(() => {
					document.getElementById('AbortNewCapture').disabled = true;
					fetchCSIFile(result.FileName);
                }, timeoutVal);
				
			}
		}
	} catch (error) {

	}
	
}

export async function abortNewCaptureHandler() {

}

export async function closeNewCaptureHandler() {
	document.getElementById('NewCaptureParams').close();
}

export async function associatedClientsHandler() {

    try {
        const response = await fetch(document.getElementById('GatewayURL').value + '/associated_clients');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const assocObj = await response.json();
		for (let i = 0; i < assocObj['AssociatedClients'].length; i++) {
			document.getElementById("SoundingDevices").add(new Option(assocObj['AssociatedClients'][i], assocObj['AssociatedClients'][i]));

		}
	} catch (error) {
		console.log('Error fetching associated clients object');
	}
}
