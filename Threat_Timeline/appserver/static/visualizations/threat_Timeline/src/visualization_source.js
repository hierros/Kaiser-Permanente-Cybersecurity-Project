/*
//Initial Design Templates by: Splunk  
//Other Contributors: D3 - D3.js version 3.3.2, Copyright © 2012, Michael Bostock 
					  D3 - D3.js Version 3.5.5, Copyright (c) 2010-2015, Michael Bostock
					  
// Creators & Contributors: Danae O'Connor, Noah Warren, and Bailey Hughes
// Last Updated: 4-16-2024

Program Purpose:
	The purpose of this program is to create a visualization for Splunk Enterprise that showcases cyber-attack data from a detection system into a series of "cards" that represent individual
	 detected attacks. In addition the visualization can sort the cards into groupings with the groupings being based on Tactic type of the cyber-attack or by the time that the cyber attack took
	 place.


	Current Bugs/Issues/Future Work Items:
	There are some issues with the timeline view:
		Primarily creating a error case for when the attacks have a time difference of 0 seconds which causes some indexing issues.
	There is a want to create some vertical spacing between the cards, but we didn't have time to implement the vertical card spacing properly.

*/

//Previous Programmers & Contributions:
//Noah Warren's Contributions:
/*
	Primary source of the d3 visualization infrastructure.
	Primary creator of the Tactic View & its various features including the data sorting in accordance to the MITRE priority, card-stacking mechanics, and the text wrapping.
*/


//Danae O'Connor's contributions:
/*
	Commenter, code cleaner, and code merger.
	Primary contributor of the Timeline View
	Primary creator of the Splunk-D3 formmatter tools, CSS creations, & default variables.
	Helped to create spacing rules, adjusted formats for card-preview readablity, and other detail modifications like text spacing and card-preview sizes.
*/

//Bailey Hughes contributions:
/*
	Partial construction of the tool tip that was overhaulled by Noah Warren and Danae O'Connor. 
	- Was removed from the team in November of 2023.
*/


const { format } = require("d3");


//Define the libraries for calls between Splunk and other libraries.
define([
	'jquery',
	'underscore',
	'api/SplunkVisualizationBase',
	'api/SplunkVisualizationUtils',
	'd3'
],
function(
	$,
	_,
	SplunkVisualizationBase,
	SplunkVisualizationUtils,
	d3
) 

{ 
//Start of the program!

return SplunkVisualizationBase.extend({


//Initializes the calls and items for the visualization.
initialize: function() {
	// Save this.$el for convenience
	this.$el = $(this.el);
	
	// Add a css selector class
	this.$el.addClass('splunk-threat-Timeline'); //calls the CSS that is within the visualization

	//These are items that supposedly help process data but there are issues with data viewing underneath the visualization that are not controlled by this product.
	//this.chunk = 50000;
	//this.offset = 0;

},


//Finds the amount of data to be processed and the output form its expected to be in - this case is Row Major Output Mode from Splunk.
getInitialDataParams: function() {
	return ({
		outputMode: SplunkVisualizationBase.ROW_MAJOR_OUTPUT_MODE,
		count: 10000
	});
},



//This is where the visualization is created and controlled.
updateView: function(data, config) {

//console.log("UpdateView data = ", data); //DEBUGGING!!! - Displays the data that the application is getting from Splunk.
//console.log("config = ", config); //DEBUGGING!!! - Displays the formatter and other default variables that are from other files.
	
	//-- "Global" Variable set up for the two views implemented: Tactic View & Timeline View.
	
	var dataRows = data.rows; //Grab the data from the Splunk background and puts it into the dataRows variable.
	
	//Sets up the data fields that are needed for the visualization to function. 
	
	//Created by Noah.
	var tacticField;		//tacticField = the tactic assocaiated with the cyber attack.
	var	techniqueField;		//techniqueField = the technique used in the attack. 
	var techniqueIdField;	//techniqueIdField = the MITRE technique id for the technique of the attack - usually technique dependent
	var descriptionField;	//descriptionField = the description of the attack as classified by MITRE. 
	var	timeField;			//timeField = the time that the attack took place - date format is: yyyy-mm-dd- hh:mm:ss.sss+00:00
	var titleField;			//titleField is a name given to the attack which is custom and user made. 
							// for the titleField there are no connections to MITRE or other standards we are aware of.
	
	
	//This determines which rows or coloumns that the data object Splunk uses contains each of the above variables and gives the index of that field.
	//Created by Noah.
	for (var i = 0; i < data.fields.length; i++) 
	{
		switch (data.fields[i].name) 
		{
			case "tactic":
				tacticField = i;
				break; 
			case "technique":
				techniqueField = i;
				break;
			case "technique_id":
				techniqueIdField = i;
				break;
			case "description":
				descriptionField = i;
				break;
			case "_time":
				timeField = i;
				break;
			case "title":
				titleField = i;
				break;
		}
	}


	//This variable grabs the User's desired view via the formatter and the savedsearches.conf files.
	// The variable is updated by the User's answer to the question "Go to Timeline View?" with a Yes or No answer.
	// If the variable is a "No" (the default value) - the Tactic View is selected.
	// If the variable is a "Yes" - the Timeline View is selected.
	//Created by Danae.
	var viewTime_TF = config[this.getPropertyNamespaceInfo().propertyNamespace+ 'viewTime_TF'] || "No";


	//The following variables are the colors of the Tactic Types.
	//The variable names are either the Tactic's name or a shortened versions of the Tactic's name followed by "_Color" to prevent confusion.
	//These variables are changable by the user and are connected via the formatter and the savedsearches.conf files.
	//Created by Danae.
	var Recon_Color = config[this.getPropertyNamespaceInfo().propertyNamespace+ 'Recon_Color'] || "#f9e98e"; //Reconnaissance color.
	
	var ReSrs_Color = config[this.getPropertyNamespaceInfo().propertyNamespace+ 'ReSrs_Color'] || "#ffd060"; // Resource Development color.

	var InAccess_Color = config[this.getPropertyNamespaceInfo().propertyNamespace+ 'InAccess_Color'] || "#ffc336"; //Initial Access color.

	var Execute_Color = config[this.getPropertyNamespaceInfo().propertyNamespace+ 'Execute_Color'] || "#ff9946"; //Execution color.

	var Persist_Color = config[this.getPropertyNamespaceInfo().propertyNamespace+ 'Persist_Color'] || "#f28123"; //Persistence color.
	
	var PrivEscal_Color = config[this.getPropertyNamespaceInfo().propertyNamespace+ 'PrivEscal_Color'] || "#e06e11";//Privilege Escalation color.

	var DefceEvad_Color = config[this.getPropertyNamespaceInfo().propertyNamespace+ 'DefceEvad_Color'] || "#d1580d";//Defense Evasion color.

	var CredAccess_Color = config[this.getPropertyNamespaceInfo().propertyNamespace+ 'CredAccess_Color'] || "#ff9595";//Credential Access color.

	var Discov_Color = config[this.getPropertyNamespaceInfo().propertyNamespace+ 'Discov_Color'] || "#ff6e6b";//Discovery color.

	var LatMove_Color = config[this.getPropertyNamespaceInfo().propertyNamespace+ 'LatMove_Color'] || "#ff5753";//Lateral Movement color.

	var Collect_Color = config[this.getPropertyNamespaceInfo().propertyNamespace+ 'Collect_Color'] || "#fe3e39";//Collection color.

	var ComNCon_Color = config[this.getPropertyNamespaceInfo().propertyNamespace+ 'ComNCon_Color'] || "#fc0607";//Command and Control color.

	var Exfilt_Color = config[this.getPropertyNamespaceInfo().propertyNamespace+ 'Exfilt_Color'] || "#db0202";//Exfiltration color.

	var Impact_Color = config[this.getPropertyNamespaceInfo().propertyNamespace+ 'Impact_Color'] || "#c71818";//Impact color.
	

	var BackGrnd_Color = "#ffffff"; // Color of the Background of the visualization.

	//Set height and width for the display canvas.
	var margins = { top: 10, right: 10, bottom: 60, left: 10 }; // Define margins
	var width = 1500 - margins.left - margins.right; // Calculate width of the chart area
	var height = 1065 - margins.top - margins.bottom; // Calculate height of the chart area

	//Sets the height of the bar of the x-axis on the Tactic View.
	var barHeight = 50; //  

	//Containers heights and widths to detrmine other items such as scroll-bars and placements :
	var containerHeight = 500; // Sets height for on screen region
	var containerWidth = 1500; // Sets width for on screen region
	
	//Controls the default card-preview heights and widths - this is altered slightly with the x-axis rangeRoundBands() function later.
	var cardHeight = 100; 	// Card height automatically set to 100 px. This helps determine vertical placements in columns.
	var cardWidth = 115; 	// Card width automatically set to 115 px. This helps determine the horizontal placement.



// --- XXXX --- TACTIC VIEW start!!!//

//Start of the massive switch statement to find the view that is wanted for the information.
if(viewTime_TF === "No") // START of Tactic View 
{

	// check for data
	if (!dataRows || dataRows.length === 0 || dataRows[0].length === 0) {
		return this;
	}

	// Guard for empty data
	if(data.rows.length < 1){
		return;
	}

	// Clear the div
	this.$el.empty();
 

	var tacticsArr = []; //Array for holding the tactics that are in the data being called.

	//Grabbing and pushing the data into the tacticsArr
	for (var i = 0; i < data.rows.length; i++) 
	{
		tacticsArr.push(data.rows[i][tacticField]);
	}

	

	//The wanted capitalization of the data.
	var capitalizedTactics = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"];
	
	
	//This function finds the unique tactics in the data set and returns a list of those unique tactics for use.
	//Created by Noah
	function findUnique(arr) {
		var uniqueTactics = [];
		for (var i = 0; i < arr.length; i++) {
			if (uniqueTactics.indexOf(arr[i]) === -1)
				{// If indexOf returns -1, then there is no index for that value and it's not in the array yet.
					uniqueTactics.push(arr[i]);
				}
			}
		return uniqueTactics;
	}

	//The variable to store unqiue tactics that calls the findUnique function with the retreived data.
	var uniqueTactics = findUnique(tacticsArr);


	//Function to go through the tactic array given to process it into the uppercase split by spaces format for the d3 elements to function - created by Noah.
	function formatTactic(tactic) {
		var formattedTactic = ''; // Empty string to store the formatted tactic
		var words = tactic.split('-'); // Try splitting on dashes
		
		if(words.length == 1) { // If the length is 1, the tactic didn't get properly split on dashes, so they are seperated by spaces
			words = tactic.split(' '); // Try splitting on spaces
		}

		for(var i = 0; i < words.length; i++) {

			var word = words[i].charAt(0).toUpperCase() + words[i].slice(1); // Capitalizes the first character of each word before re-combining it with the rest of the word
			if (word == "And") { // Handling the special case where you don't want to capitalize "and" for "Command and Control"
				word = "and";
			}

			formattedTactic += word // Adding the now capitalized word to the formatted tactic

			if (i != words.length - 1) { // Assuming this isn't the last word, we want a space between words
				formattedTactic += ' ';
			}
		}

		return formattedTactic; // Return the newly formatted tactic
	}


	var formattedTactics = []; // Buffer to store the newly formatted tactics


	for (var i = 0; i < uniqueTactics.length; i++) { // Formatting the uniqueTactics array used as the domain
		formattedTactics.push(formatTactic(uniqueTactics[i])); 
	}

	for(var i = 0; i < data.rows.length; i++) { // Runs the formatter on every tactic in the current dataset
		data.rows[i][tacticField] = formatTactic(data.rows[i][tacticField]);
	}


//console.log("Formatted Tactics: ", formattedTactics); //DEBUGGING!!! - Testing if the formatting was done correctly

	//Function to sort the formatted tactics based on the wanted capatalized tactics array obtained from MITRE database. This sorts it in MITRE order.
	//Created by Noah.
	formattedTactics.sort(function(a, b) {
		return capitalizedTactics.indexOf(a) - capitalizedTactics.indexOf(b); // Swaps the values if the result of the operation is positive, i.e. if a > b. No swap if a < b
		});
	
//console.log("Formatted Tactics: ",formattedTactics); //DEBUGGING!!! - Checking to see if the 


	var tacticsLeng = formattedTactics.length; //This helps to create card-preview widths that fit onto the canvas created for the visualization.
	var TempCardWidth = cardWidth; //default to 115 px card Width

	//Small function the adjusts the card-preview widths depending on the number of tactic types found. 
	//  If the tactics found is large - the card-preview size will be small, if the tactics found is small - the card previews will be large.
	//Created by Danae.
	if(tacticsLeng <=14 && tacticsLeng > 10) //11 to 14 tactics get this size for card Width
	{
		TempCardWidth = 100;
	}
	else if (tacticsLeng <=10 && tacticsLeng > 5) //5 to 10 tactics gets this size for card Width
	{
		TempCardWidth = 115;
		
	}
	else if (tacticsLeng <=5 && tacticsLeng > 0) //Less than 5 tactics gets this size for card Width
	{
		TempCardWidth = 115 * 2.5;
	}
	

	//-- Visualization Creation:

	//Create the Container for the visualization - allows for scroll bars
	var container = d3.select(this.el).append("div")
		.style("height", containerHeight + "px")
		.style("width", containerWidth + "px")
		.style("overflow", "auto")
		.style("position", "relative");


	//Create background of the visualization and its behavior.
	var chart = container.append("svg")
		.attr("width", width + margins.left + margins.right)
		//.attr("width" , (cardWidth*tacticsLeng + cardWidth*2) + margins.left + margins.right)
		.attr("height", height + margins.top + margins.bottom)
		.append("g")
		.attr("transform", "translate(" + margins.left + "," + margins.top + ")");

	//Creates the color and other attributes of the visualization background
	chart.append("rect")
		.attr("x", -margins.left)
		.attr("y", -margins.top)
		.attr("width", "100%")
		.attr("height", "100%")
		.attr("fill", BackGrnd_Color);
		//.attr("fill", "#f4f4f4"); // Original BackGrnd_Color


	//Create the x axis associated with the view on the background
	var x = d3.scale.ordinal()
		.domain(formattedTactics)
		.rangeRoundBands([0, width]); //controls the size of the x-axis 
		

	//This creates the labels that go with the x axis on the background. Takes the tactic names and splits them across the " " characters
	// Created by Noah
	chart.append("g")
		.attr("transform", "translate(0," + barHeight + ")")
		.call(d3.svg.axis()
			.scale(x)
			.orient("top"))
			.selectAll('.tick text')
		.call(function(t){
			t.each(function(d){
				var self = d3.select(this);
				var s = self.text().split(" "); //This splits the titles of the area on the spaces associated with them 
				self.text('');
				
				//Sorting Mechanism for axis lable placement. -- Danae
				if (s[2] != null){
					//For 3 word titles
					//console.log("Hit the s[2]");
					self.append("tspan")
						.attr("x", 0)
						.attr("dy","-2.5em")
						.text(s[0]);
					self.append("tspan")
						.attr("x", 0)
						.attr("dy","1em")
						.text(s[1]);
					self.append("tspan")
						.attr("x", 0)
						.attr("dy","1em")
						.text(s[2]);
				}
				else if (s[1] != null){
					//For 2 word titles
					//console.log("Hit s[1]");
					self.append("tspan")
						.attr("x", 0)
						.attr("dy","-2em")
						.text(s[0]);
					self.append("tspan")
						.attr("x", 0)
						.attr("dy","1em")
						.text(s[1]);
				}
				else if (s[0] != null){
					//For 1 word titles
					//console.log("Hit s[0] - 1.5");
					self.append("tspan")
						.attr("x", 0)
						.attr("dy","-1.5em")
						.text(s[0]);
				}
				

			})
		})



	//This is for coloring the X-axis in accordance with the Tactics. - Created by Noah.
	var coloredBars = chart.selectAll(".coloredBars")
		.data(uniqueTactics)
		.enter()
		.append('g')
		.attr('transform', (d) => {
			return "translate(" + (x(d) ) + "," + (barHeight - 6) + ")"; //Aligns the cards and the colored bars together. More information at the bars.append item below.
			});


//Can be either for DEBUGGING or for Future improvement:
//This adds color to the x axis so that the columns have associated colors to their tactic type. 
// Was removed by Client but helpful for debugging - keep opacity at 0 for no showing on visualization.
	coloredBars.append("rect")
		.style("opacity", 1)
		.attr("width", TempCardWidth) 	//Uses the card width to make the colored part of the x-axis.
		.attr("height", 6) 			//This is the height of the x-axis.
		.style("fill", function(d)
		{//Fills in the color of the bars.
			if (d == "reconnaissance")
				{
					return Recon_Color;
				}        else if (d == "Resource Development")
				{
					 return ReSrs_Color;
				}        else if (d == "Initial Access")
				{
					return InAccess_Color;
				}        else if (d == "Execution")
				{
					return Execute_Color;
				}        else if (d == "Persistence")
				{
					return Persist_Color;
				}        else if (d == "Privilege Escalation")
				{
					return PrivEscal_Color;
				}        else if (d == "Defense Evasion")
				{
					return DefceEvad_Color;
				}        else if (d == "Credential Access")
				{
					return CredAccess_Color;
				}        else if (d == "Discovery")
				{
					return Discov_Color;
				}        else if (d == "Lateral Movement")
				{
					return LatMove_Color;
				}        else if (d == "Collection")
				{
					return Collect_Color;
				}        else if (d == "Command and Control")
				{
					return ComNCon_Color;
				}        else if (d == "Exfiltration")
				{
					return Exfilt_Color;
				}        else if (d == "Impact")
				{
					return Impact_Color;
				}        else
				 {
					 return "white";
				}
				
		 })
		 .style("opacity", 0);


	let tacticCount = {}; //Creates an empty dictionary to hold the cards.

	//Creates the cards/bar's associated with tactics and adjusts their heights in accordance to the available information. - Created by Noah.
	var bars = chart.selectAll(".bars")
		.data(dataRows)
		.enter()
		.append('g')
		.attr('transform', (d) => {
			tacticCount[d[tacticField]] = (tacticCount[d[tacticField]] || 0) + 1
			//The return statement makes the following position placements:
			// Takes the data's tactic field and find its placement on the x axis - this is the x position.
			// Takes the cardheight * its placement in the stack to calculate the initial y that does not account for the x-axis placement on the canvas. 
			// To get the true y: subtract the (cardhight - barHeight + 10) to get the y placement that doesn't stick to the x-axix but still have it related to the x-axis.
			//	- Created by Danae
			return "translate(" + (x(d[tacticField])) + "," + (cardHeight * tacticCount[d[tacticField]] - (cardHeight - barHeight)+10) + ")";
		});


	//This actually attatches the bars to the view. - Created by Noah.
	bars.append("rect")
		.style("fill", function(d) //Places color into the cards, currently used for debugging and in the Timeline View - Created by Danae.
		{
			/*
			if (d[tacticField] == "credential-access")
			{
				return CredAccess_Color;
			}
			
			else if (d[tacticField] == "discovery")
			{
				return Discov_Color;
			}
			
			else if (d[tacticField] == "lateral-movement")
			{
				return LatMove_Color;
			}
			
			else if (d[tacticField] == "collection")
			{
				return Collect_Color;
			}
			
			else if (d[tacticField] == "command-and-control")
			{
				return ComNCon_Color;
			}
			else if (d[tacticField] == "exfiltration")
			{
				return Exfilt_Color;
			}
			
			else if (d[tacticField] == "impact")
			{
				return Impact_Color;
			}
			
			else
			{
				 return "white";
			}*/
			return "white";
		})
		.style("opacity", 0) //This controls the opacity of the above color which acts as the back of the card.
		.style("stroke", "#ebd2be") //This controls the border of the cards - primarily used for debugging/future use.
		.style("stroke-width", 1)
		.style("border", "solid")
		.style("border-width", "1px")
		.style("border-radius", "5px")
		.attr("width", TempCardWidth)
		.attr("height", cardHeight);


	//This is the tool tip to give information about the attack given the location of the item. - Created by Noah.
	var tooltip = d3.select(this.el)
		.append("div")
		.style("opacity", 0)
		.attr("class", "tooltip") //Makes the tooltip appear
		.style("background-color", "white")
		.style("border", "solid")
		.style("border-width", "1px")
		.style("border-radius", "5px")
		.style("width", "700px") 	//Added by Noah
		.style("padding", "10px");

//Created by Noah
	bars.on("click", function(d) 
	{
		tooltip.transition()
			.duration(200)
			.style("opacity", 0.9)
			.style("left", "50px")
			.style("top", "75px");

		tooltip.html( //Done by Danae.
					"<font size=" + "3" + "><b><i>" + d[titleField] + "</i></b> </font>" + "<br>"  //Sets up the title font-size and special features
					+ "<font size=" + "2" + ">" + d[techniqueIdField] + " - " + d[techniqueField] + "</font>" + "<br>" //Sets up the technique items font-size and special features.
					+ d[descriptionField] + "<br>" 	//Sets up the items for the description
					+ d[timeField]					//Sets up the items for the description
					)
			.style("color", "black");
			
		//Created by Noah
		var closeButton = tooltip.append("div")
			.style("position", "absolute")
			.style("right","8px") //Modified by Danae
			.style("top","-4px")
			.style("cursor", "pointer")
			.attr("class","closeButton-form")
			.html("x")
			.on("click", function(d)
			{
				tooltip.style("display","none");
			});

		tooltip.style("display", "block");
	});
	


	//Text for the Title
	bars.append("text")
		 //.attr("class", "bar-text")
		 .text(function(d) {
			 return d[titleField];
		 })
		.attr("x", 0)	//Sets the original x position to 0.
		.attr("y", 10)	//Sets the original y position to 10.
		.attr("dx", 5)	//Sets the offset of x to 5. - Created by Danae
		.attr("dy", 2)	//Sets the offset of y to 2. - Created by Danae
		.attr("class", "title-form") // CSS call - Created by Danae
		.style("text-align", "center")
		.style("fill", "black")
		//.style("text-anchor", "left")
		//.style("font-size", "9px")
		.call(function(t){                 // Adds text wrapping to the title
			t.each(function(d) {
					var self = d3.select(this);
					var s = self.text().split(' ');
					self.text('');
					var lineCount = 0;
					var tspan = self.append("tspan") // Appending first tspan
						.attr("x", 0)
						.attr("dx", TempCardWidth * 0.1)
						//.attr("dx", cardWidth * 0.1)
						.attr("dy", "1em");
						
						for (var i = 0; i < s.length; i++) {
							var currentWord = s[i];
							tspan.text(tspan.text() + " " + currentWord);
							
							//To return to previous "static" card width replace "TempCardWidth" with "cardWidth"

							if (tspan.node().getComputedTextLength() > (TempCardWidth - TempCardWidth * 0.1)) {                            
							
								tspan.text(tspan.text().slice(0, -currentWord.length)); // Remove the last word if we are greater than the cardWidth                            
								if (lineCount < 1) {  // Checking to see if we've reached the maximum line count                                
								tspan = self.append("tspan")
										.attr("x", 0)
										.attr("dx", TempCardWidth * 0.1)
										.attr("dy", "1em")
										.text(currentWord);
								}
								else {
									tspan.text(tspan.text() + " ...");
									break; // If the lineCount == 4, we don't want to have any more
								}
								lineCount++;
							}
						}
			})
		});




	//Text for the techniqueField - made by Noah
	bars.append("text")
		.text(function(d) {			
			return d[techniqueIdField] + " - " + d[techniqueField];
		})
		//.attr("x", cardWidth / 2)
		//.attr("x", cardWidth * 0.1) //Sets the offset of the first technique item to act as padding to 0.1 of the cardWidth - Created by Danae
		.attr("x", TempCardWidth * 0.1)
		.attr("y", 50)
		.style("text-anchor", "left")
		.attr("class","technique-form") //Applies CSS - Created by Danae.
		.style("fill", "black")
		.call(function(t){                
			t.each(function(d) {
					var self = d3.select(this);
					var s = self.text().split(' ');
					self.text('');
					var lineCount = 1; //This is the starting line count.
					var tspan = self.append("tspan") // Appending first tspan
						.attr("x", 0)
						.attr("dx", TempCardWidth * 0.1)
						.attr("dy", "1em");
						
						for (var i = 0; i < s.length; i++) {
							var currentWord = s[i];
							tspan.text(tspan.text() + " " + currentWord);

							if (tspan.node().getComputedTextLength() > (TempCardWidth - TempCardWidth * 0.1)) {                            
								
								tspan.text(tspan.text().slice(0, -currentWord.length)); // Remove the last word if we are greater than the cardWidth                            
								if (lineCount < 3) {  // Checking to see if we've reached the maximum line count                                
								tspan = self.append("tspan")
										.attr("x", 0)
										.attr("dx", TempCardWidth * 0.1)
										.attr("dy", "1em")
										.text(currentWord);
								}
								else {
									tspan.text(tspan.text() + " ...");
									break; // If the lineCount == 4, we don't want to have any more
								}
								lineCount++;
							}
						}
			})
		});

	
console.log("Data after: ", data); //DEBUGGING!!! Checking to see that data is updaing properly!
	
} // END of Tactic View




// --- XXXX --- TIMELINE VIEW START!!!//


// START of Timeline View of the attacks
else
{
	//Taken in part from the tactic view made by Noah Warren above
	//Modifications to make it into the timeline view done by Danae O'Connor

	// check for data
	if (!dataRows || dataRows.length === 0 || dataRows[0].length === 0) {
		return this;
	}

	// Guard for empty data
	if(data.rows.length < 1){
		return;
	}

	// Clear the div
	this.$el.empty();


	//Grabs the data and then sorts the data based off of the time field to sort the time in assending order (min time to max time).
	var sortedData;
	sortedData = dataRows.sort(function(a,b) {return a[timeField] > b[timeField];});
	

	var TimeStampsArr = []; //Takes in the tactics of each item.

	//Populates the Tactics of the given data
	for (var i = 0; i < data.rows.length; i++) 
	{
		TimeStampsArr.push(dataRows[i][timeField]);
	}
	
//console.log("Unsorted Array: ", dataRows); //DEBUGGING!!!
//console.log("Sorted Array: ", sortedData);  //DEBUGGING!!!
//console.log("Timestamp Array: ", TimeStampsArr); //DEBUGGING!!!

	//Create the minimum time from the data, the maximum time from the data, and the time difference between the two.
	var minTime = 0;
	var maxTime = 0;
	var Time_Diff = 0;

	//Gets the dates for the begining time (minimum/min time) and ending time (maximum/max time) using the sorted data
	minTime = new Date(sortedData[0][timeField]);
	maxTime = new Date(sortedData[data.rows.length-1][timeField]);
 
	//Gets the time difference of the minimum time and the maximum time.	
	Time_Diff = maxTime.getTime() - minTime.getTime();

//console.log("minTime: ", minTime.getTime(), " is: ", minTime); //DEBUGGING!!!
//console.log("maxTime: ", maxTime.getTime(), " is: ", maxTime); //DEBUGGING!!!
//console.log("Time Difference ", Time_Diff); //DEBUGGING!!!

	//Time chunk variable default. This variable helps to know how many columns to divide the data into for time periods. The default is 4 time period chunks.	
	var chunks = 4;


	//This if-else block statment determines the amount of columns or timeslice "chunks" needed to divide the data into. - Created by Danae.
	// The count starts from 0 - so a chunks of 23 is actually 24 time chunks for something like the 24 hours in a single day.
	if(Time_Diff <= 60000) //Less than or equal to a minute
	{	
		chunks = 59;
	}
	else if (Time_Diff <= 3600000) //Less than or equal to an hour
	{
		chunks = 59;
	}
	else if (Time_Diff <= 86400000) //Less than or equal to a day
	{	
		chunks = 23;
	}
	else if (Time_Diff <= 604800000) //Less than or equal to a week
	{	
		chunks = 6;
	}
	else if (Time_Diff <= 2629800000) //Less than or equal to a month
	{
		chunks = 3;
	}
	else if (Time_Diff == 0)
	{
		chunks = 1;
		
	}
	else	//Defaulted value for if none of the items work.
	{
		chunks = 4;
	}


//console.log("Chunk var: ", chunks); //DEBUGGING!!!


	//Gets the partition of times to define the boundaries of each time chunk.
	var timePartSize = Time_Diff / chunks;
	
	let timeList = {};		//This is the list of time boundaries
	let DisplayTime = {}; 	//Currently a temporary unused dictionary of the strings of the date-time

	var chunkList = []; //This contains the number of chunks that are needed to sort all of the avaliable data into. This governs display.


	chunkList.push(0); 					//This pushes the first chunk on to the pile - enables the start of sorting.
	timeList[0] = minTime.getTime(); 	//Defines the first element of time to compare to
	DisplayTime[0] = minTime;			//Gets the string of the first element of time.
	
	//Time partitioner or "chunker" - takes the times available and defines the boundry of each chunk of time to allow for sorting into chunks.
	for (var wark = 1; wark < chunks; wark++)
	{
		timeList[wark] = minTime.getTime() + (timePartSize * wark); //Time boundary [x] = minTime + (Time partition * [x chunk variable])
		DisplayTime[wark] = new Date(timeList[wark]); 				//adds in the display of the time chunks name.
		chunkList.push(wark);										//pushes the chunk into the chunk list for x.
	
	}

	timeList[chunks] = maxTime.getTime(); 	//Adds the final elememnt to the time chunk with the maxTime as nothing can exceed this time.
	DisplayTime[chunks] = maxTime;			//Adds the display name of the date
	chunkList.push(chunks);					//Adds the last variable of the chunks to the list of sorting partitions

//console.log("chunk list ", chunkList); //DEBUGGING!!!
//console.log("Timelist: ", timeList); //DEBUGGING!!!
//console.log("Display Time: ", DisplayTime); //DEBUGGING!!!



//Card building
let cardBuild = {};	
	var senti = 10000; //Temp sentinel value to prevent while loop from running off
	var Idex = 0;



//Goes through all elements sorts them into their sections of the time period defined.
while (Idex < data.rows.length && Idex != senti)
{
	timeHold = new Date(sortedData[Idex][timeField]);
	
	for (var par = 0; par <= chunks; par++)
	{	
		//Once time for object is found - does a calculation to find its height for display as well as adjusting the count for if future items are needed to be calculated.
		if (timeHold >= timeList[par] && timeHold <= timeList[par+1])
		{
			cardBuild[timeList[par]] = (cardBuild[timeList[par]] || 0 ) + 1; //Double checks if it has been added to the list and adds to the item if there is already something there.
			sortedData[Idex][7] = cardBuild[timeList[par]];		
			sortedData[Idex][6] = par; 

		}
	}
	
	Idex = Idex + 1; //Update the index value.
}

//console.log("organized data: ", sortedData);
	


	//Create background of the visualization
	var container = d3.select(this.el).append("div")
		.style("height", containerHeight + "px")
		.style("width", containerWidth + "px")
		.style("overflow", "auto")
		.style("position", "relative");
	
	
	
	//Create background of the visualization
	var chart = container.append("svg")
		.attr("width", (cardWidth*chunks + cardWidth*2) + margins.left + margins.right)
		.attr("height", height + margins.top + margins.bottom)
		.append("g")
		.attr("transform", "translate(" + margins.left + "," + margins.top + ")");

	chart.append("rect")
		.attr("x", -margins.left)
		.attr("y", -margins.top)
		.attr("width", "100%")
		.attr("height", "100%")
		.attr("fill", BackGrnd_Color);
		//.attr("fill", "#f4f4f4");

	//Create the x axis associated on the background
	var x = d3.scale.ordinal()
		.domain(chunkList) 
		.rangeRoundBands([0, (cardWidth*chunks + cardWidth*2)]);

console.log("Range band:", x.rangeBand());//DEBUGGING!!!
console.log("The range:", x.range());
console.log("cardWidth * chunks + cardWidth*2, na");

	//Appends the x axis onto the background  
	chart.append("g")
		.attr("transform", "translate(0," + (height - 30) + ")")
		.call(d3.svg.axis()
			.scale(x)
			.orient("bottom"))
			.selectAll('.tick text')


	var maskedBar = chart.selectAll(".maskedBar")
		.data(chunkList)
		.enter()
		.append('g')
		.attr('transform', (d) => {

			return "translate(" + (x(d) - 8) + "," + (height - 30+6) + ")";
		});

	maskedBar.append("rect")
		.style("opacity", 1)
		.attr("width", cardWidth+100)
		.attr("height", 30)
		.style("fill", BackGrnd_Color);
		//.style("fill", "#f4f4f4");
		
//console.log("Changed height xd-8, height 50, height + 6");
	
	maskedBar.append("text")
		.text(function(d){
			return DisplayTime[d];
		})
		.attr("x", cardWidth)
		.attr("y", 0.5)
		.style("text-anchor", "left")
		.style("fill", "black")
		.call(function(t){
			t.each(function(d) {
					var self = d3.select(this);
					var s = self.text().split(' ');
					self.text('');
					var lineCount = 0;
					var tspan = self.append("tspan") // Appending first tspan
						.attr("x", 0)
						.attr("dx", cardWidth * 0.1)
						.attr("dy", "1em");
						
						for (var i = 0; i < s.length; i++) {
							var currentWord = s[i];
							tspan.text(tspan.text() + " " + currentWord);

							if (tspan.node().getComputedTextLength() > (cardWidth - cardWidth * 0.1)) {                            
							
								tspan.text(tspan.text().slice(0, -currentWord.length)); // Remove the last word if we are greater than the cardWidth                            
								if (lineCount < 4) {  // Checking to see if we've reached the maximum line count                                
								tspan = self.append("tspan")
										.attr("x", 0)
										.attr("dx", cardWidth * 0.1)
										.attr("dy", "1em")
										.text(currentWord);
								}
								else {
									tspan.text(tspan.text() + " ...");
									break; // If the lineCount == 4, we don't want to have any more
								}
								lineCount++;
							}
						}
			})
		});



	//Creates the "card" presentation objects via creating a "bar" and then calculating where it will show up on the visualization.
	var bars = chart.selectAll(".bars")
		.data(sortedData)
		.enter()
		.append('g')
		.attr('transform', (d) => 
		{
			console.log("x(d[6]):", x(d[6]));
			return "translate(" + x(d[6]) + "," + (height-30 - cardHeight * d[7]) + ")";
		}
	);


	//This fills in the details of the card - primarily border color, width, and height.
	//Fill in cards based on how the time relates to the dictionary list item starting with element 1 which is the smallest in the available time slot.
	bars.append("rect")
		.style("fill", BackGrnd_Color)
		//.style("fill", "#f4f4f4")
		.style("stroke", function(d)
			 {//Created by Danae
				//Finds the color associated with each card.
				if (d[tacticField] == "Reconnaissance")
				{
					return Recon_Color;
				}
				else if (d[tacticField] == "Resource Development")
				{
					 return ReSrs_Color;
				}
				
				else if (d[tacticField] == "Initial Access")
				{
					return InAccess_Color;
				}
				
				else if (d[tacticField] == "Execution")
				{
					return Execute_Color;
				}
				
				else if (d[tacticField] == "Persistence")
				{
					return Persist_Color;
				}
				
				else if (d[tacticField] == "Privilege Escalation")
				{
					return PrivEscal_Color;
				}
				
				else if (d[tacticField] == "Defense Evasion")
				{
					return DefceEvad_Color;
				}
				
				else if (d[tacticField] == "Credential Access")
				{
					return CredAccess_Color;
				}
				
				else if (d[tacticField] == "Discovery")
				{
					return Discov_Color;
				}
				
				else if (d[tacticField] == "Lateral Movement")
				{
					return LatMove_Color;
				}
				
				else if (d[tacticField] == "Collection")
				{
					return Collect_Color;
				}
				
				else if (d[tacticField] == "Command and Control")
				{
					return ComNCon_Color;
				}
				else if (d[tacticField] == "Exfiltration")
				{
					return Exfilt_Color;
				}
				
				else if (d[tacticField] == "Impact")
				{
					return Impact_Color;
				}
				
				else
				 {
					 return "cyan";
				}
			})
		.style("stroke-opacity", 1)
		.style("stroke-width", 3)
		.attr("width", cardWidth)
		.attr("height", cardHeight);

//console.log("Stroke opacity = 1");

	//This is the tool tip to give information about the attack given the location of the item. - Created by Noah.
	var tooltip = d3.select(this.el)
		.append("div")
		.style("opacity", .5)
		.attr("class", "tooltip") //Makes the tooltip appear
		.style("background-color", "white")
		.style("border", "solid")
		.style("border-width", "1px")
		.style("border-radius", "5px")
		.style("width", "700px") 	//Added by Noah
		.style("padding", "10px");


	//Created by Noah
	bars.on("click", function(d) 
	{
		tooltip.transition()
			.duration(200)
			.style("opacity", 0.9)
			.style("left", "50px")
			.style("top", "75px");

		tooltip.html( //Done by Danae.
					"<font size=" + "3" + "><b><i>" + d[titleField] + "</i></b> </font>" + "<br>"  //Sets up the title font-size and special features
					+ "<font size=" + "2" + ">" + d[techniqueIdField] + " - " + d[techniqueField] + "</font>" + "<br>" //Sets up the technique items font-size and special features.
					+ "<font size=" + "2" + ">" + d[tacticField] + "</font>" + "<br>" //Sets up the tactic items font-size and special features.
					+ d[descriptionField] + "<br>" 	//Sets up the items for the description
					+ d[timeField]					//Sets up the items for the description
					
					)
			.style("color", "black");
			
		//Created by Noah
		var closeButton = tooltip.append("div")
			.style("position", "absolute")
			.style("right","8px") //Modified by Danae
			.style("top","-4px")
			//.style("cursor", "default")
			.style("cursor", "pointer")
			.attr("class","closeButton-form")
			.html("x")
			.on("click", function(d)
			{
				tooltip.style("display","none");
			});

		tooltip.style("display", "block");
	});
	


	//Text for the Title
	bars.append("text")
		//.attr("class", "bar-text")
		.text(function(d) {
			return d[titleField];
		})
		.attr("x", 0)	//Sets the original x position to 0.
		.attr("y", 10)	//Sets the original y position to 10.
		.attr("dx", 5)	//Sets the offset of x to 5. - Created by Danae
		.attr("dy", 2)	//Sets the offset of y to 2. - Created by Danae
		.attr("class", "title-form") // CSS call - Created by Danae
		.style("text-anchor", "left")
		.style("fill", "black")
		//.style("text-align", "center")
		//.style("text-anchor", "left")
		//.style("font-size", "9px")
		
		// Adds text wrapping to the title
		.call(function(t){
				t.each(function(d) {
						var self = d3.select(this);
						var s = self.text().split(' ');
						self.text('');
						var lineCount = 0;
						var tspan = self.append("tspan") // Appending first tspan
							.attr("x", 0)
							.attr("dx", cardWidth * 0.1)
							.attr("dy", "1em");
							
							for (var i = 0; i < s.length; i++) {
								var currentWord = s[i];
								tspan.text(tspan.text() + " " + currentWord);

								if (tspan.node().getComputedTextLength() > (cardWidth - cardWidth * 0.1)) {
								
									tspan.text(tspan.text().slice(0, -currentWord.length)); // Remove the last word if we are greater than the cardWidth
									if (lineCount < 2) {  // Checking to see if we've reached the maximum line count
										tspan = self.append("tspan")
											.attr("x", 0)
											.attr("dx", cardWidth * 0.1)
											.attr("dy", "1em")
											.text(currentWord);
									}
									else {
										tspan.text(tspan.text() + " ...");
										break; // If the lineCount == 4, we don't want to have any more
									}
									lineCount++;
								}
							}
				})
			});


	//Text for the techniqueField - made by Noah
	bars.append("text")
		.text(function(d) {			
			return d[techniqueIdField] + " - " + d[techniqueField];
		})
		//.attr("x", cardWidth / 2)
		.attr("x", cardWidth * 0.1) //Sets the offset of the first technique item to act as padding to 0.1 of the cardWidth - Created by Danae
		.attr("y", 50)
		.style("text-anchor", "left")
		.attr("class","technique-form") //Applies CSS - Created by Danae.
		.style("fill", "black")
		.call(function(t){                
			t.each(function(d) {
					var self = d3.select(this);
					var s = self.text().split(' ');
					self.text('');
					var lineCount = 1; //This is the starting line count.
					var tspan = self.append("tspan") // Appending first tspan
						.attr("x", 0)
						.attr("dx", cardWidth * 0.1)
						.attr("dy", "1em");
						
						for (var i = 0; i < s.length; i++) {
							var currentWord = s[i];
							tspan.text(tspan.text() + " " + currentWord);

							if (tspan.node().getComputedTextLength() > (cardWidth - cardWidth * 0.1)) {                            
								
								tspan.text(tspan.text().slice(0, -currentWord.length)); // Remove the last word if we are greater than the cardWidth                            
								if (lineCount < 3) {  // Checking to see if we've reached the maximum line count                                
								tspan = self.append("tspan")
										.attr("x", 0)
										.attr("dx", cardWidth * 0.1)
										.attr("dy", "1em")
										.text(currentWord);
								}
								else {
									tspan.text(tspan.text() + " ...");
									break; // If the lineCount == 4, we don't want to have any more
								}
								lineCount++;
							}
						}
			})
		});


container.node().scrollTop = container.node().scrollHeight;		//	This ensures that the scrollbar starts at the bottom of the visualization

}//END of Timeline View

	//This chunk code is in the tutorial visualization but it halts the updating of data without the initialze function but does not show information at bottom of visualization!
	//this.offset += dataRows.length;
	//this.updateDataParams({count: this.chunk, offset: this.offset});  
	//console.log("Checking If update");
	}
});
});