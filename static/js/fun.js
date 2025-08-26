let userWalletAddress = null;

// Function to fetch the wallet address
async function fetchAddress() {
  // Specify the options for getting the address
  const getAddressOptions = {
    payload: {
      purposes: ['ordinals', 'payment'],
      message: 'Address for receiving Ordinals and payments',
      network: {
        type: 'Mainnet',
      },
    },
    onFinish: async (response) => {
      // Log the full response to debug
      console.log("Full response:", response);
      
      // Find the address with purpose 'ordinals'
      const targetAddressObj = response.addresses.find(addr => addr.purpose === 'ordinals');
      
      // Check if the address is found and then display it
      if (targetAddressObj && targetAddressObj.address) {
        userWalletAddress = targetAddressObj.address;
        
        // Update the DOM with the fetched address
        document.getElementById('display-address').innerText = `Your Address: ${userWalletAddress}`;
        

      } else {
        console.error('No suitable address found in the response.');
      }
    }
  };
  
  // Assuming getAddress is a function provided by your SDK
  await getAddress(getAddressOptions);
}

   async function sendDataToMongoDB(data, endpoint) { // <-- Mak
  try {
    const response = await fetch(endpoint, { 
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(data),
    });

    const jsonResponse = await response.json();
    if (jsonResponse.status === 'success') {
      console.log('Successfully saved to MongoDB.');
    } else {
      console.log('Failed to save to MongoDB:', jsonResponse.reason);
    }
  } catch (error) {
    console.error('Failed to save to MongoDB:', error);
  }
}

// Function to inscribe the image
async function inscribeImage() {
  if (selectedBase64Image === "") {
    alert('Please select an image first.');
    return;
  }

  const content = selectedBase64Image;
  const appFeeAddress = "bc1q7smayz55k67k79ek5ey4x7mp5zprer5pwfwlxn";
  const appFee = 2000;
  const contentType = "image/png";
  const payloadType = "BASE_64";

  // Increment counter here, before sending the payload
  try {
    const response = await fetch("/increment_counter", { method: 'POST' });
    const jsonResponse = await response.json();
    if (jsonResponse.status === 'success') {
      getCounter();  // Refresh the counter display
    }
  } catch (error) {
    console.error("Failed to increment counter:", error);
  }

  await createInscription({
    payload: {
      network: {
        type: 'Mainnet',
      },
      contentType,
      content,
      payloadType,
      appFeeAddress,
      appFee,
    },
    onFinish: async (response) => {
      document.getElementById('addressDisplay').innerHTML += `<br/>Transaction ID: ${response.txId}`;
    },
    onCancel: () => alert("Canceled"),
  });
}

document.addEventListener('DOMContentLoaded', (event) => {
  document.getElementById('get-address-button').addEventListener('click', fetchAddress);

  const inscribeButton = document.getElementById('inscribeButton');
  inscribeButton.addEventListener('click', function() {
    inscribeImage();
  });
});


document.addEventListener('DOMContentLoaded', function () {
  const testButton = document.getElementById('testButton');
  
  testButton.addEventListener('click', function() {
    // Add a random Transaction ID for test
    const randomID = Math.floor(Math.random() * 10000);
    
    // Add this ID to the addressDisplay div
    document.getElementById('addressDisplay').innerText = "Transaction ID: " + randomID;
  });
});

function getCounter() {
  fetch('/get_counter')  // Making a GET request to the '/get_counter' route
    .then(response => response.json())
    .then(data => {
      const counterElement = document.getElementById('inscribed');  // Getting the element where counter value will be displayed
      counterElement.textContent = data.count;  // Updating the counter value
    });
}

// Initial fetch to populate the counter when the page loads
getCounter();

// Optionally, you can update the counter value at regular intervals
setInterval(getCounter, 900000); 

