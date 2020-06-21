from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IParameter
import json
import base64

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    
    #
    # Implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
        # Keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # Obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # Set our extension name
        callbacks.setExtensionName("Decode JWT")
        
        # Register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(self)
        
    # 
    # Implement IMessageEditorTabFactory
    #
    
    def createNewInstance(self, controller, editable):
        # Create a new instance of our custom editor tab
        return Base64InputTab(self, controller, editable)
        
# 
# Class implementing IMessageEditorTab
#

class Base64InputTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._editable = editable
        
        # Create an instance of Burp's text editor, to display our deserialized data
        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(editable)
        
    #
    # Implement IMessageEditorTab
    #

    def getTabCaption(self):
        return "Decode JWT"
        
    def getUiComponent(self):
        return self._txtInput.getComponent()
        
    def isEnabled(self, content, isRequest):
        # Enable this tab for requests containing a Bearer Token
        headers = self._extender._helpers.analyzeRequest(content).getHeaders()
        if isRequest and any("Authorization: Bearer" in h for h in headers):
        	bearer_token = None
        	for h in headers:
        		if "Authorization: Bearer" in h:
        			bearer_token = h.split()[2]
        			if bearer_token is not None and '.' in bearer_token:
        				return True
        			return False
				return False
		return False


    def setMessage(self, content, isRequest):
        if content is None:
            # Clear our display
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)
        
        else:
            # Retrieve the Bearer token
            headers = self._extender._helpers.analyzeRequest(content).getHeaders()
            bearer_token = None
            for h in headers:
            	if "Authorization: Bearer" in h:
            		bearer_token = h.split()[2]

            jwt = None
            if bearer_token == None:
				msg = "An error occurred while fetching the JWT"
				self._txtInput.setText(msg)
				self._txtInput.setEditable(self._editable)
            else:
                # Get the parts of the JWT
                jwt = bearer_token.split('.')
                jwt_header = jwt[0]
                jwt_payload = jwt[1]

                missing_padding = len(jwt_header) % 4
                for i in range(missing_padding):
                    jwt_header = jwt_header + "="

                jwt_header = base64.b64decode(jwt_header)

                missing_padding = len(jwt_payload) % 4
                for i in range(missing_padding):
                    jwt_payload = jwt_payload + "="

                jwt_payload = base64.b64decode(jwt_payload)

                # Format the parts to look nice
                jwt_header_bytes = json.loads(jwt_header)
                jwt_header_json = json.dumps(jwt_header_bytes, indent=4, sort_keys=True)
                jwt_payload_bytes = json.loads(jwt_payload)
                jwt_payload_json = json.dumps(jwt_payload_bytes, indent=4, sort_keys=True)

                # Create the final output
                output = jwt_header_json + "\n" + jwt_payload_json

                self._txtInput.setText(output)
                self._txtInput.setEditable(self._editable)

            self._txtInput.setEditable(self._editable)
        
        # Remember the displayed content
        self._currentMessage = content

    def getMessage(self):
        # 
        if self._txtInput.isTextModified():
            # 
            text = self._txtInput.getText()
            input = text
            
            # Update the request with the new parameter value
            return self._extender._helpers.updateParameter(self._currentMessage, self._extender._helpers.buildParameter("JWT", input, IParameter.PARAM_BODY))
            
        else:
            return self._currentMessage

    def isModified(self):
        return self._txtInput.isTextModified()
    
    def getSelectedData(self):
        return self._txtInput.getSelectedText()