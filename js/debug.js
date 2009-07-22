$(document).ready(function() {
  var db = openDatabase("signers", "0.1", "Message Signers Database", 200000);
  
  db.transaction(function(tx) {
    tx.executeSql("SELECT COUNT(*) AS count FROM signers", [], function(tx, result) {
      $('#debug-signers-count').html('0/'+result.rows.item(0).count);
    });
  });
  
  
  
  $('#debug-signers-count').html('0/');

  $('#debug-hash').html(SHA1($('#message').attr('value')));
  
  
  $('#debug-hash').html(SHA1($('#message').attr('value')));

  $('#message').change(function() {
    $('#debug-hash').html(SHA1(this.value));
  });
  
});
