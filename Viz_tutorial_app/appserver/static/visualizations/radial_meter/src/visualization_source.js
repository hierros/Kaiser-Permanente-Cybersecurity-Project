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

return SplunkVisualizationBase.extend({

initialize: function() {
    // Save this.$el for convenience
    this.chunk = 50000;
    this.offset = 0;

    this.$el = $(this.el);
     
    // Add a css selector class
    this.$el.addClass('splunk-radial-meter');
},

getInitialDataParams: function() {
    return ({
        outputMode: SplunkVisualizationBase.ROW_MAJOR_OUTPUT_MODE,
        count: 10000
    });
},

updateView: function(data, config) {
      // get data
      var dataRows = data.rows;

      // check for data
      if (!dataRows || dataRows.length === 0 || dataRows[0].length === 0) {
          return this;
      }
   // Guard for empty data
   if(data.rows.length < 1){
    return;
}
// Take the first data point
datum = data.rows[0][0];
// Clear the div
this.$el.empty();

// Pick a color for now
var mainColor = 'yellow';
// Set domain max
var maxValue = 100;

// Set height and width
var height = 220;
var width = 220;

// Create a radial scale representing part of a circle
var scale = d3.scale.linear()
    .domain([0, maxValue])
    .range([ - Math.PI * .75, Math.PI * .75])
    .clamp(true);

// Create parameterized arc definition
var arc = d3.svg.arc()
    .startAngle(function(d){
        return scale(0);
    })
    .endAngle(function(d){
        return scale(d)
    })
    .innerRadius(70)
    .outerRadius(85);

// SVG setup
var svg  = d3.select(this.el).append('svg')
    .attr('width', width)
    .attr('height', height)
    .style('background', 'white')
    .append('g')
    .attr('transform', 'translate(' + width / 2 + ',' + height / 2 + ')');

// Background arc
svg.append('path')
    .datum(maxValue)
    .attr('d', arc)
    .style('fill', 'lightgray');

// Fill arc
svg.append('path')
    .datum(datum)
    .attr('d', arc)
    .style('fill', mainColor);

// Text
svg.append('text')
    .datum(datum)
    .attr('class', 'meter-center-text')
    .style('text-anchor', 'middle')
    .style('fill', mainColor)
    .text(function(d){
        return parseFloat(d);
    })
    .attr('transform', 'translate(' + 0 + ',' + 20 + ')');
   

        // fetch the next chunk after processing the current chunk
        this.offset += dataRows.length;
        this.updateDataParams({count: this.chunk, offset: this.offset});
}
});
});