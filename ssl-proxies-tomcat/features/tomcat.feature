Feature: Run Tomcat with proxy certificate support

	When Tomcat is running with ssl proxy certificate support, a valid proxy certificate should be
	able to connect successfully, while an invalid cert should be rejected.
	
	Scenario: Valid Client Certificate
		Given Tomcat is configured with ssl proxy support enabled
		And Tomcat is running with a valid certificate
		When A client presents a valid certificate
		Then The client can successfully connect to the server
		And The server shuts down  
	
	Scenario: Invalid Client Certificate
		Given Tomcat is configured with ssl proxy support enabled
		And Tomcat is running with an valid certificate
		When A client presents a invalid certificate
		Then The client can successfully connect to the server
		And The server shuts down