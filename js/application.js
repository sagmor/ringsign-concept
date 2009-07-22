function flash(type, message) {
  var error;
  
  if (type == "error")
    error = true
  else if (type == "notice")
    error = false
  else
    return;
  
  var widget = $('<div class="ui-widget"> <div class="ui-state-'+(error ? 'error' : 'highlight')+
                ' ui-corner-all" style="margin-top: 20px; padding: 0 .7em;"><p><span class="ui-icon ui-icon-'+
                (error ? 'alert' : 'info')+'" style="float: left; margin-right: .3em;"></span><strong>'+
                (error ? 'Alert:' : 'Hey!')+'</strong> '+message+'.</p></div></div>');
  widget.click(function() {
    $(this).slideUp("slow", function() { $(this).remove(); });
  });
  widget.hide();
  $("#flash").append(widget);
  widget.slideDown("slow");
  if (!error) {
    setTimeout(function(){widget.click();},4000);
  }
}

var db;

try {
  if (window.openDatabase) {
    db = openDatabase("signers", "0.1", "Message Signers Database",1);
    if (!db)
      flash("error", "Failed to open the database on disk.  This is probably because the version was bad or there is not enough space left in this domain's quota");
    else
      $(document).ready(initApplication);
  } else
    flash("error", "Couldn't open the database.  Please try with a WebKit nightly with this feature enabled");
} catch(err) { }


function initApplication() {
  db.transaction(function(tx) {
    tx.executeSql("SELECT COUNT(*) FROM signers", [], function() {
      flash("notice", "Database Loaded!");
    }, 
    function(tx, error) {
      tx.executeSql("CREATE TABLE signers ("+
                      "id INTEGER PRIMARY KEY,"+
                      "name VARCHAR(255) NOT NULL, "+
                      "email VARCHAR(150) NOT NULL, "+
                      "n TEXT NOT NULL, "+
                      "e TEXT, "+
                      "key_id INTEGER UNIQUE,"+
                      "created_at REAL)");
      tx.executeSql("CREATE TABLE keys ("+
                      "id INTEGER PRIMARY KEY,"+
                      "p TEXT NOT NULL, "+
                      "q TEXT NOT NULL, "+
                      "d TEXT NOT NULL, "+
                      "dmp1 TEXT NOT NULL, "+
                      "dmq1 TEXT NOT NULL, "+
                      "coeff TEXT NOT NULL)");
      flash("notice", "Database Created!");
    });
  });
  
  db.transaction(function(tx) {
    tx.executeSql("SELECT * FROM signers", [], function(tx, results) {
      $.each(results.rows, function(i) {
        row = results.rows.item(i);
        showSigner(row['id'], row['name'], row['email'], !!row['key_id']);
      });
    });
  });
  
  $("#available-signers, #signers").sortable({
  			connectWith: 'ul',
  			placeholder: 'ui-state-highlight'
  		}).disableSelection();
  
  $("#signers-box").accordion({ header: "h2" });
  
  // Set up connections
  $('#sign').click(function() {
    //Collect Signers
    var members = new Array($("#signers li").length);
    var signer;
    
    $("#signers li").each(function (i, object) {
      members[i] = object.key;
      
      if ($(object).find('input:checked').length > 0) {
        signer = i;
      }
    });
    
    //var members = new Array(members_ids.length);
    //for (var i=0; i < members_ids.length; i++) {
    //  members[i] = getKeyOf(members_ids[i]);
    //};
    
    try {
      var signature = ring_sign($('#message').attr('value'), members, signer);
      window.console.log(signature);

      flash("notice", "The message has been signed");
      $('#signature').attr('value', JSON.stringify(signature) );
      
    } catch(err) {
      window.console.log(err);
    }
   
    return false;
  });
  
  $('#validate').click(function() {
    var members = new Array($("#signers li").length);
    
    $("#signers li").each(function (i, object) {
      members[i] = object.key;
    });
    
    try {
    signature = JSON.parse( $('#signature').attr('value') );
    
      var result = ring_valid ($('#message').attr('value'), signature.v, signature.x, members)
      
      if (result) {
        alert('Firma Válida!');
      } else {
        alert('Firma Inválida!');
      }
      
    } catch(err) {
      window.console.log(err);
    }
    
    return false;      
  });
  
  $('#signer-save').click(function() {
    var
      name = $('#signer-name').attr('value'),
      email = $('#signer-email').attr('value'),
      modulus = $('#signer-modulus').attr('value'),
      exponent = $('#signer-exponent').attr('value'),
      created_at = new Date();
      
    db.transaction(function(tx) {
      tx.executeSql("INSERT INTO signers (name, email, n, e, created_at) VALUES (?,?,?,?,?)", 
        [name, email, modulus, exponent, created_at], function(tx, result) {
          id = result.insertId;
          showSigner(id, name, email, false);
          flash("notice", "User Saved!");
        }, function(tx,error) {
          flash("error", "An error ocurred while trying to save the user!<br /> ("+error.message+")");
        });
    });
    return false;
  });
  
  $('#key-generate').click(function() {
    try {
      var startTime = new Date();
      var rsa = new RSAKey();
      
      rsa.generate(512, '10001');
      $('#key-p').attr('value', rsa.p.toString(16));
      $('#key-q').attr('value', rsa.q.toString(16));
      $('#key-d').attr('value', rsa.d.toString(16));
      $('#key-e').attr('value', rsa.e.toString(16));
      $('#key-n').attr('value', rsa.n.toString(16));
      $('#key-dmp1').attr('value', rsa.dmp1.toString(16));
      $('#key-dmq1').attr('value', rsa.dmq1.toString(16));
      $('#key-coeff').attr('value', rsa.coeff.toString(16));
      
      
      var endTime=new Date();
      flash("notice", "New 512 bit key generated in "+(endTime.getTime()-startTime.getTime())/1000.0+' seconds')
    } catch(err) {
      flash("error", "Couldn't generate key!<br /> ("+err.message+")");
      return false;
    }
    
    return false;
  });
  
  $('#key-save').click(function() {
    var
      name = $('#key-name').attr('value'),
      email = $('#key-email').attr('value'),
      p = $('#key-p').attr('value'),
      q = $('#key-q').attr('value'),
      d = $('#key-d').attr('value'),
      e = $('#key-e').attr('value'),
      n = $('#key-n').attr('value'),
      dmp1 = $('#key-dmp1').attr('value'),
      dmq1 = $('#key-dmq1').attr('value'),
      coeff = $('#key-coeff').attr('value'),
      created_at = new Date();
      
    db.transaction(function(tx) {
      tx.executeSql("INSERT INTO keys (p, q, d, dmp1, dmq1, coeff) VALUES (?, ?, ?, ?, ?, ?)", 
                    [p, q, d, dmp1, dmq1, coeff], function(tx, result) {
        key_id = result.insertId
        tx.executeSql("INSERT INTO signers (name, email, n, e, key_id, created_at) VALUES (?,?,?,?,?,?)", 
          [name, email, n, e, key_id, created_at], function(tx, result) {
            id = result.insertId;
            showSigner(id, name, email, true);
            flash("notice", "User Saved!");
          })
      }, function(tx,error) {
        flash("error", "An error ocurred while trying to save the key!<br /> ("+error.message+")");
      }); 
    });
    return false;
  });


  

}

function showSigner(id, name, email, key) {
  signer = $('<li id="signer-'+id+'">'+(key ? '<input type="radio" name="key" value="'+id+'"/> ': '')+
  name+' &lt;'+email+'&gt;</li>');
  
  delete_link = $(' <a href="#'+id+'">X</a>');
  delete_link.click(function() {
    db.transaction(function(tx) {
      if (key) {
        tx.executeSql("SELECT key_id FROM signers WHERE id=?",[id], function(tx, results) {
          if (results.rows.item(0)['key_id'])
            tx.executeSql("DELETE FROM keys WHERE id=?",[results.rows.item(0)['key_id']])
        });
      }
      
      tx.executeSql("DELETE FROM signers WHERE id=?",[id]);
    });
    $(this).parent('li').remove();
  });
  
  signer[0].key = getKeyOf(id);
  
  signer.append(delete_link);
  
  $('#available-signers').append(signer);
}

function getKeyOf (id) {
  var key = new RSAKey();
  
  db.transaction(function(tx) {
    tx.executeSql("SELECT * FROM signers WHERE id = ?", [id], function(tx,results) {
      result = results.rows.item(0);
      if (result['key_id']) {
        tx.executeSql("SELECT * FROM keys WHERE id=?", [result['key_id']], function(tx,results2) {
          result2 = results2.rows.item(0);
          
          key.setPrivate(result['n'], result['e'], result2['d']);
          //key.setPrivateEx(result['n'], result['e'], result2['d'], result2['p'], result2['q'], result2['dmp1'], result2['dmq1'], result2['coeff']);
        });
        
      } else {
        key.setPublic(result['n'], result['e']);
      }
      
    }, function(tx,err) { alert(err.message); return null; });
  });
  
  return key;
}


