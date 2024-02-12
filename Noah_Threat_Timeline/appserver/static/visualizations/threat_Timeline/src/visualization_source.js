/*
//Creators & Contributors: Danae O'Connor, Noah Warren, and Bailey Hughes
//Initial Design Templates by: Splunk  
//Other Contributors: D3 - D3.js version 3.3.2, Copyright © 2012, Michael Bostock 
//			
// Last Updated: 2-6-2024
// Program Purpose:
//
// Current Bugs:
//
*/

//Noah Warren's contributions:
/*
	Primary source of the d3 visualization infrastructure.
	Primary creator of the Tactic View & its various features including MITRE priority sort and its format.
*/


//Danae O'Connor's contributions:
/*
	Commenter, code cleaner, and code merger
	Primary contributor of the Timeline View
	Primary creator of the Splunk-D3 formmatter tools, CSS, & defaults.
	
*/

//Bailey Hughes contributions:
/*
	Partial construction of the tool tip. 
	- Was removed from the team in November of 2023.
*/


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
) { 
//Start of the program!

return SplunkVisualizationBase.extend({


//Initializes the calls and items for the visualization.
initialize: function() {
	// Save this.$el for convenience
	this.$el = $(this.el);
	
	// Add a css selector class
	this.$el.addClass('splunk-threat-Timeline'); //calls the CSS that is within the visualization
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
	
	//Variable set up for the two views implemented: Tactic View & Timeline View.
	
	
	var dataRows = data.rows; //Grab the data from the Splunk background and throw it into the dataRows variable.
	
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
			//Should install a "default" but don't know what would be a good catch that wont kill Splunk on contact. //DEBUGGING!!!
		}
	}



	//This variable grabs the User's desired view via the formatter and the savedsearches.conf files.
	// If the variable is a No (the default value) - the Tactic View is selected.
	// If the variable is a Yes - the Timeline View is selected.
	//Created by Danae.
	var viewTime_TF = config[this.getPropertyNamespaceInfo().propertyNamespace+ 'viewTime_TF'] || "No";


	//The following variables are the colors of the Tactic Types.
	//The variable names are either the Tactic name or a shortened versions of the Tactic's name followed by "_Color" to prevent confusion.
	//These variables are changable by the user and are connected via the formatter and the savedsearches.conf files.
	//Created by Danae.
	var Recon_Color = config[this.getPropertyNamespaceInfo().propertyNamespace+ 'Recon_Color'] || "#f9e98e"; // reconnaissance color.
	
	var ReSrs_Color = config[this.getPropertyNamespaceInfo().propertyNamespace+ 'ReSrs_Color'] || "#ffd060"; // resource-development color.

	var InAccess_Color = config[this.getPropertyNamespaceInfo().propertyNamespace+ 'InAccess_Color'] || "#ffc336"; //initial-access color.

	var Execute_Color = config[this.getPropertyNamespaceInfo().propertyNamespace+ 'Execute_Color'] || "#ff9946"; //execution color.

	var Persist_Color = config[this.getPropertyNamespaceInfo().propertyNamespace+ 'Persist_Color'] || "#f28123"; //persistence color.
	
	var PrivEscal_Color = config[this.getPropertyNamespaceInfo().propertyNamespace+ 'PrivEscal_Color'] || "#e06e11";//privilege-escalation color.

	var DefceEvad_Color = config[this.getPropertyNamespaceInfo().propertyNamespace+ 'DefceEvad_Color'] || "#d1580d";//defense-evasion color.

	var CredAccess_Color = config[this.getPropertyNamespaceInfo().propertyNamespace+ 'CredAccess_Color'] || "#ff9595";//credential-access color.

	var Discov_Color = config[this.getPropertyNamespaceInfo().propertyNamespace+ 'Discov_Color'] || "#ff6e6b";//discovery color.

	var LatMove_Color = config[this.getPropertyNamespaceInfo().propertyNamespace+ 'LatMove_Color'] || "#ff5753";//lateral-movement color.

	var Collect_Color = config[this.getPropertyNamespaceInfo().propertyNamespace+ 'Collect_Color'] || "#fe3e39";//collection color.

	var ComNCon_Color = config[this.getPropertyNamespaceInfo().propertyNamespace+ 'ComNCon_Color'] || "#fc0607";//command-and-control color.

	var Exfilt_Color = config[this.getPropertyNamespaceInfo().propertyNamespace+ 'Exfilt_Color'] || "#db0202";//exfiltration color.

	var Impact_Color = config[this.getPropertyNamespaceInfo().propertyNamespace+ 'Impact_Color'] || "#c71818";//impact color.
	



// Set height and width for the display canvas.
	var margins = { top: 10, right: 10, bottom: 60, left: 10 }; // Define margins
	var width = 1500 - margins.left - margins.right; // Calculate width of the chart area
	var height = 1065 - margins.top - margins.bottom; // Calculate height of the chart area


//Containers heights and widths to detrmine other items such as scroll-bars and placements :
	var containerHeight = 500; // Sets height for on screen region
	var containerWidth = 1500; // Sets width for on screen region
	var cardHeight = 50; // Card height automatically set to 50 px. This helps determine vertical placements in columns.
	var barHeight = 50; // Sets the height of the bar of the x-axis on the Tactic View. 
	var cardWidth = 70; // Card width automatically set to 70 px. This helps determine the horizontal placement.

// --- XXXX --- //

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

//console.log('Time View is on - Value = ', viewTime_TF); //DEBUGGING!!!
//console.log('Data from Splunk:', data); //DEBUGGING!!!

	var tacticsArr = []; //Array for holding the tactics that are in the data being called.

	//Grabbing and pushing the data into the tacticsArr
	for (var i = 0; i < data.rows.length; i++) 
	{
		tacticsArr.push(data.rows[i][tacticField]);
	}

//console.log('tacticField: ', tacticField); //DEBUGGING!!!
//console.log(tacticsArr); //DEBUGGING!!!

	
	//Tactics Names in accordance to MITRE
	var tactics = ["reconnaissance", "resource-development", "initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement", "collection", "command-and-control", "exfiltration", "impact"];

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

	//The variable to store unqiue tactics 
	var uniqueTactics = findUnique(tacticsArr);
	console.log(uniqueTactics); //DEBUGGING!!!


	//Function to sort uniqueTactics based on the tactics array obtained from MITRE database. This sorts it in MITRE order.
	uniqueTactics.sort(function(a, b) {
		return tactics.indexOf(a) - tactics.indexOf(b);// Swaps the values if the result of the operation is positive, i.e. if a > b. No swap if a < b
		});
		
//console.log(uniqueTactics);//DEBUGGING!!!



	//Create the Container for the visualization - allows for scroll bars
	var container = d3.select(this.el).append("div")
		.style("height", containerHeight + "px")
		.style("width", containerWidth + "px")
		.style("overflow", "auto")
		.style("position", "relative");


	//Create background of the visualization and its behavior.
	var chart = container.append("svg")
		.attr("width", width + margins.left + margins.right)
		.attr("height", height + margins.top + margins.bottom)
		.append("g")
		.attr("transform",
			"translate(" + margins.left + "," + margins.top + ")");

	//Creates the color and other attributes of the visualization background
	chart.append("rect")
		.attr("x", -margins.left)
		.attr("y", -margins.top)
		.attr("width", "100%")
		.attr("height", "100%")
		.attr("fill", "#f4f4f4");

	//Create the x axis associated with the view on the background
	var x = d3.scale.ordinal()
		.domain(uniqueTactics)
		.rangeRoundBands([0, width], .4);
 
	//This creates the labels that go with the x axis on the background. Takes the tactic names and splits them across the "-" characters
	chart.append("g")
		.attr("transform", "translate(0," + barHeight + ")")
		.call(d3.svg.axis()
			.scale(x)
			.orient("top"))
			.selectAll('.tick text')
		.call(function(t){
			t.each(function(d){
				var self = d3.select(this);
				var s = self.text().split("-"); //This splits the titles of the area on the spaces associated with them
				self.text('');
				self.append("tspan")
					.attr("x", 0)
					.attr("dy","-2em")
					.text(s[0]);
				self.append("tspan")
					.attr("x", 0)
					.attr("dy","1em")
					.text(s[1]);
				self.append("tspan")
					.attr("x", 0)
					.attr("dy","1em")
					.text(s[2]);
			})
		})

	//This is for coloring the X-axis in accordance with the Tactics. - Created by Noah.
	var coloredBars = chart.selectAll(".coloredBars")
		.data(uniqueTactics)
		.enter()
		.append('g')
		.attr('transform', (d) => {      
			return "translate(" + x(d) + "," + (barHeight - 6) + ")";
			});

	coloredBars.append("rect")
		.style("opacity", 1)
		.attr("width", x.rangeBand())
		.attr("height", 6)
		.style("fill", function(d)
		{//Fills in the color of the bars.
			if (d == "reconnaissance")
				{
					return Recon_Color;
				}        else if (d == "resource-development")
				{
					 return ReSrs_Color;
				}        else if (d == "initial-access")
				{
					return InAccess_Color;
				}        else if (d == "execution")
				{
					return Execute_Color;
				}        else if (d == "persistence")
				{
					return Persist_Color;
				}        else if (d == "privilege-escalation")
				{
					return PrivEscal_Color;
				}        else if (d == "defense-evasion")
				{
					return DefceEvad_Color;
				}        else if (d == "credential-access")
				{
					return CredAccess_Color;
				}        else if (d == "discovery")
				{
					return Discov_Color;
				}        else if (d == "lateral-movement")
				{
					return LatMove_Color;
				}        else if (d == "collection")
				{
					return Collect_Color;
				}        else if (d == "command-and-control")
				{
					return ComNCon_Color;
				}        else if (d == "exfiltration")
				{
					return Exfilt_Color;
				}        else if (d == "impact")
				{
					return Impact_Color;
				}        else
				 {
					 return "white";
				}
		 });


	let tacticCount = {}; //Creates an empty dictionary to hold the cards.

	//Creates the cards/bar's associated with tactics and adjusts their heights in accordance to the available information. - Created by Noah.
	var bars = chart.selectAll(".bars")
		.data(dataRows)
		.enter()
		.append('g')
		.attr('transform', (d) => {
			tacticCount[d[tacticField]] = (tacticCount[d[tacticField]] || 0) + 1
			return "translate(" + x(d[tacticField]) + "," + (barHeight * tacticCount[d[tacticField]]) + ")";
		});


	//This actually attatches the bars to the view. - Created by Noah.
	bars.append("rect") /*
		.style("fill", function(d) //Places color into the cards - Created by Danae. Only used for debugging purposes at the moment
		{
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
			}
		 }) */
		 .style("opacity", 0)
		 .style("stroke", "black")
		 .style("stroke-width", 1)
		 .attr("width", x.rangeBand())
		 .attr("height", cardHeight);


	//This is the tool tip to give information about the attack given the location of the item. - Created by Noah.
	var tooltip = d3.select(this.el)
		.append("div")
		.attr("class", "tooltip")
		.style("opacity", 0)
		.style("background-color", "white")
		.style("border", "solid")
		.style("border-width", "1px")
		.style("border-radius", "5px")
		.style("width", "700px")
		.style("padding", "10px");

	//While on the chart - track the mouse position and show the tooltip. - Created by Noah
/*	chart.on("mousemove", function()
	{
		var mousePos = d3.mouse(this);
		
		tooltip.style("left", + (mousePos[0]+20) + "px") //Tightend position by Danae.
			.style("top", + (mousePos[1]+40)+ "px");
	});

	//While the mouse is over a card the transition of the tooltip obeyes the following rools and shows the followi.
	bars.on("mouseover", function(d) 
		{
			tooltip.transition()
				.duration(200)
				.style("opacity", 0.9);

			tooltip.html(d[titleField] + "<br>"  + d[techniqueIdField]
			 + " - " + d[techniqueField] + "<br>" + d[descriptionField] + "<br>" + d[timeField])
				.style("color", "black")
		})

	//When the mouse goes off the card - turns the card off by reducing opacity.
	.on("mouseout", function(d) 
	{
		tooltip.transition()
			.duration(250)
			.style("opacity", 0);
	});
*/
	tooltip.append("text")
	.text("x")
    .attr("x", 490) // Adjust as needed
    .attr("y", 10) 
	.style("cursor", "pointer")
	.on("click", function() {
		tooltip.style("display", "none"); // Hides the tooltip
	});
	bars.on("click", function(d) 
	{
		tooltip.transition()
			.duration(200)
			.style("opacity", 0.9)
			.style("left", "50px")
			.style("top", "75px");

		tooltip.html(d[titleField] + "<br>"  + d[techniqueIdField]
		+ " - " + d[techniqueField] + "<br>" + d[descriptionField] + "<br>" + d[timeField])
			.style("color", "black")
		
		tooltip.style("display", "block");
	});
	tooltip.on("click", function(d)
	{
		tooltip.style("display", "none");
	});

	bars.append("text")
		 .text(function(d) {
			 return d[titleField];
		 })
		.attr("x", x.rangeBand() / 2)
		.attr("y", 10)
		//.style("text-anchor", "left")
		.attr("class", "title-form") // CSS call - Created by Danae
		.style("text-align", "center")
		.style("fill", "black");

	var textBars = bars.append("div")
	.attr("x", 0)
	.attr("y", 15)
	.style("fill", "black")
	.attr("class", "technique-form");
	//.text(function(d) { return d[techniqueField]; }); // One method tried for adding text
	textBars.html(function(d) {
		return d[techniqueField]; // Another attempted method, uses html to append the text
	});
	// Append text to each bar container, currently commented out to attempt text wrapping
	/*
	textBars.append("text")
		.attr("class", "technique-form")
		.text(function(d) { return d[techniqueField]; });
*/
	/*
	bars.append("text")
		.text(function(d) {
			return d[techniqueField];
		}) 
		.call(function(t){ //Code re-use of Noah's title splitter.
			//The longest technique name in the MITRE database is "Linux and Mac File and Directory Permissions Modification"
			t.each(function(d){
				//Since this is 8 words long, we need to display up to s[7]
				var self = d3.select(this);
				var s = self.text().split(' ');
				self.text('');
				self.append("tspan")
					.attr("x", 0)
					.attr("dy","1em")
					.text(s[0])
				self.append("tspan")
					.attr("x", 0)
					.attr("dy","1em")
					.text(s[1])
				self.append("tspan")
					.attr("x", 0)
					.attr("dy","1em")
					.text(s[2])
				if (s[3] != undefined) {
					self.append("tspan")
						.attr("x", 0)
						.attr("dy","1em")
						.text("...");
				}
			})
		}) 
		.attr("x", x.rangeBand() / 2)
		.attr("y", 15)
		.style("text-anchor", "left")
		.attr("class","technique-form") //Applies CSS - Created by Danae.
		//style("font-size", "9px")
		.style("fill", "black"); */

//container.node().scrollTop = container.node().scrollHeight;		//	This ensures that the scrollbar starts at the bottom of the visualization, not used in this view currently

} // END of Tactic View




// --- XXXX --- //



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
	
	console.log("Unsorted Array: ", dataRows); //DEBUGGING!!!
	console.log("Sorted Array: ", sortedData);  //DEBUGGING!!!

	var TimeStampsArr = []; //Takes in the tactics of each item.

	//Populates the Tactics of the given data
	for (var i = 0; i < data.rows.length; i++) 
	{
		TimeStampsArr.push(dataRows[i][timeField]);
	}

//Testing data from splunk and testing the switching values of the formatter.
//console.log('Tactic View is on True - Value = ', viewTime_TF); //DEBUGGING!!!
//console.log('Data from Splunk:', data); //DEBUGGING!!!

//console.log("Timestamp Array: ", TimeStampsArr); //DEBUGGING!!!
//console.log("Time Field: ", timeField); //DEBUGGING!!!

	//Create the minimum time from the data, the maximum time from the data, and the time difference between the two.
	var minTime = 0;
	var maxTime = 0;
	var Time_Diff = 0;

//Gets the dates for min and max using the sorted data
	minTime = new Date(sortedData[0][timeField]);
	maxTime = new Date(sortedData[data.rows.length-1][timeField]);

		
	//Potential catch mechanism if the data doesn't sort properly.
/*	for(var eep = 0; eep < data.rows.length; eep++)
	{
		var holdsIt = new Date(timesInArr[eep])
		
		if (minTime > holdsIt) //If the value is smaller than the current time, make it the new smallest Time
		{
			minTime = holdsIt;
			console.log("New minTime found!");
			//break;
		}
		
		if (maxTime < holdsIt) //If the value is greater than the current time, make it the new biggest time.
		{
			maxTime = holdsIt;
			console.log("New maxTime found! Indx: ", eep);
		}
	}
 */
 
//console.log("minTime: ", minTime.getTime(), " is: ", minTime); //DEBUGGING!!!
//console.log("maxTime: ", maxTime.getTime(), " is: ", maxTime); //DEBUGGING!!!

//Gets the time difference of the minimum time and the maximum time.	
	Time_Diff = maxTime.getTime() - minTime.getTime();
	
//console.log("Time Difference ", Time_Diff); //DEBUGGING!!!

//Time chunk variable basis.	
	var chunks = 4; //This variable helps to know how many columns to divide the data into for time periods. The default is 4 time period chunks.

//This if-else block statment determines the amount of columns or "chunks" needed to divide the data into. - Created by Danae.
	if(Time_Diff <= 60000) //Less than or equal to a minute
	{	
		chunks = 60;
	}
	else if (Time_Diff <= 3600000) //Less than or equal to an hour
	{
		chunks = 60;
	}
	else if (Time_Diff <= 86400000) //Less than or equal to a day
	{	
		chunks = 24;
	}
	else if (Time_Diff <= 604800000) //Less than or equal to a week
	{	
		chunks = 7;
	}
	else if (Time_Diff <= 2629800000) //Less than or equal to a month
	{
		chunks = 4;
	}
	else	//Defaulted value for if none of the items work.
	{
		chunks = 5;
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

//console.log("DisplayTime ", DisplayTime[wark]); //DEBUGGING!!!
//console.log("Timelist at ", wark, " is: ", timeList[wark]); //DEBUGGING!!!		
	}

	timeList[chunks] = maxTime.getTime(); 	//Adds the final elememnt to the time chunk with the maxTime as nothing can exceed this time.
	DisplayTime[chunks] = maxTime;			//Adds the display name of the date
	chunkList.push(chunks);					//Adds the last variable of the chunks to the list of sorting partitions

//console.log("chunk list ", chunkList); //DEBUGGING!!!
//console.log("Timelist: ", timeList); //DEBUGGING!!!
//console.log("Display: ", DisplayTime); //DEBUGGING!!!

//Card building
let cardBuild = {};	
	var senti = 100000; //Temp sentinel value to prevent while loop from running off
	var Idex = 0;

//Goes through all elements sorts them into their sections of the time period defined.
while (Idex < data.rows.length && Idex != senti)
{
	timeHold = new Date(sortedData[Idex][timeField]);
	
	for (var par = 0; par < chunks; par++)
	{	
		//console.log("Current chunking ", par); //DEBUGGING!!!
//Once time for object is found - does a calculation to find its height for display as well as adjusting the count for if future items are needed to be calculated.
		if (timeHold >= timeList[par] && timeHold < timeList[par+1])
		{
			cardBuild[timeList[par]] = (cardBuild[timeList[par]] || 0 ) + 1;
			sortedData[Idex][7] = cardBuild[timeList[par]];
			sortedData[Idex][6] = par;
		//	console.log("cardnumb: ", cardBuild[timeList[par]]); //DEBUGGING!!!
		//	console.log("sorted column: ", sortedData[Idex][6]); //DEBUGGING!!!
		//	console.log("Title: ", sortedData[Idex][titleField]); //DEBUGGING!!!
		}

	}
	
	Idex = Idex + 1; //Update the index value.
}
	
	//DEBUGGING!!!
	//cardBuild[timeList[0]] = (cardBuild[timeList[0]] || 0) + 1;		
	//sortedData[che][7] = cardBuild[timeList[0]];
	//	sortedData[che][6] = 0; //time section

	//	console.log("time list count: ", cardBuild[timeList[0]]);
	//	console.log("sorted add: ", sortedData[che][6]);
	//	console.log("sorted row: ", sortedData[che]);	
	
	
//console.log("cardBuild: ", cardBuild);  //DEBUGGING!!!
	
	//Create background of the visualization
	var container = d3.select(this.el).append("div")
		.style("height", containerHeight + "px")
		.style("width", containerWidth + "px")
		.style("overflow", "auto")
		.style("position", "relative");
	
	
	//Create background of the visualization
	var chart = container.append("svg")//d3.select(this.el)
		//.append("svg")
		.attr("width", width + margins.left + margins.right)
		.attr("height", height + margins.top + margins.bottom)
		.append("g")
		.attr("transform",
			"translate(" + margins.left + "," + margins.top + ")");

	chart.append("rect")
		.attr("x", -margins.left)
		.attr("y", -margins.top)
		.attr("width", "100%")
		.attr("height", "100%")
		.attr("fill", "#f4f4f4");

	//Create the x axis associated on the background
	var x = d3.scale.ordinal()
		.domain(chunkList)
		.rangeRoundBands([0, width], .4);

	//Appends the x axis onto the background  
	chart.append("g")
		.attr("transform", "translate(0," + height + ")")
		.call(d3.svg.axis()
			.scale(x)
			.orient("bottom"))
			//.selectAll('.tick text')



	//Creates the "card" presentation objects via creating a "bar" and then calculating where it will show up on the visualization.
	var bars = chart.selectAll(".bars")
		.data(sortedData)
		.enter()
		.append('g')
		.attr('transform', (d) => 
		{
			return "translate(" + x(d[6]) + "," + (height - 50 * d[7]) + ")";
		}
	);
	

	//This fills in the details of the card - primarily color, width, and height.
	//fill in cards based on how the time relates to the dictionary list item starting with element 1 which is the smallest in the available time slot.
	bars.append("rect")
		.style("fill", function(d)
			 {//Created by Danae
				//Finds the color associated with each card.
				if (d[tacticField] == "reconnaissance")
				{
					return Recon_Color;
				}
				else if (d[tacticField] == "resource-development")
				{
					 return ReSrs_Color;
				}
				
				else if (d[tacticField] == "initial-access")
				{
					return InAccess_Color;
				}
				
				else if (d[tacticField] == "execution")
				{
					return Execute_Color;
				}
				
				else if (d[tacticField] == "persistence")
				{
					return Persist_Color;
				}
				
				else if (d[tacticField] == "privilege-escalation")
				{
					return PrivEscal_Color;
				}
				
				else if (d[tacticField] == "defense-evasion")
				{
					return DefceEvad_Color;
				}
				
				else if (d[tacticField] == "credential-access")
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
					 return "cyan";
				}
			})
		.style("stroke", "black")
		.style("stroke-width", 1)
		.attr("width", x.rangeBand)
		.attr("height", 50);



	//Tool tip
	var tooltip = d3.select(this.el)
		.append("div")
		.attr("class", "tooltip")
		.style("opacity", 0)
		.attr("class", "tooltip")
		.style("background-color", "white")
		.style("border", "solid")
		.style("border-width", "1px")
		.style("border-radius", "5px")
		.style("padding", "10px");

	chart.on("mousemove", function()
	{
		var mousePos = d3.mouse(this);
		
		tooltip.style("left", + (mousePos[0]+50) + "px")
			.style("top", + (mousePos[1]+50)+ "px");
	});

	bars.on("mouseover", function(d) 
	{
		tooltip.transition()
			.duration(200)
			.style("opacity", 0.9);

		tooltip.html(d[titleField] + "<br>" + d[tacticField] + "<br>" +d[techniqueIdField] + " - " +  d[techniqueField] + "<br>" + d[descriptionField] + "<br>" + d[timeField])
			//.style("left", (d3.event.pageX) + "px")
			//.style("top", (d3.event.pageY - 28) + "px")
			//.style("left", 100 + "px")
			//.style("top", 250 + "px")
			.style("color", "black")
	})

	.on("mouseout", function(d) 
	{
		tooltip.transition()
			.duration(250)
			.style("opacity", 0);
	});


	bars.append("text")
		.text(function(d) {
		return d[titleField];
		})
		.attr("x", x.rangeBand() / 2)
		.attr("y", 10)
		.style("text-anchor", "middle")
		.style("font-size", "9px")
		.style("fill", "black");

	bars.append("text")
		.text(function(d) {
			return d[techniqueField];
		})
		.call(function(t){
			//The longest technique name in the MITRE database is "Linux and Mac File and Directory Permissions Modification"
			t.each(function(d){
				//Since this is 8 words long, we need to display up to s[7]
				var self = d3.select(this);
				var s = self.text().split(' ');
				self.text('');
				self.append("tspan")
					.attr("x", 0)
					.attr("dy","1em")
					.text(s[0])
				self.append("tspan")
					.attr("x", 0)
					.attr("dy","1em")
					.text(s[1])
				self.append("tspan")
					.attr("x", 0)
					.attr("dy","1em")
					.text(s[2])
				if (s[3] != undefined) {
					self.append("tspan")
						.attr("x", 0)
						.attr("dy","1em")
						.text("...");
				}
			})
		})
		.attr("x", x.rangeBand() / 2)
		.attr("y", 20)
		.style("text-anchor", "middle")
		.style("font-size", "9px")
		.style("fill", "black");



container.node().scrollTop = container.node().scrollHeight;		//	This ensures that the scrollbar starts at the bottom of the visualization

}//END of Timeline View


	// fetch the next chunk after processing the current chunk
	this.offset += dataRows.length;
	this.updateDataParams({count: this.chunk, offset: this.offset}); 
	}
});
});