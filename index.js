const express = require('express');
const ejs = require('ejs');
const crypto = require('crypto');
var cookieParser = require('cookie-parser')
const bodyParser = require('body-parser');
const { Pool, Client } = require('pg');

const app = express();

const connectionString = `postgresql://christian:${process.env.password}@free-tier11.gcp-us-east1.cockroachlabs.cloud:26257/defaultdb?sslmode=verify-full&options=--cluster%3Dweb-store-1836`;

const pool = new Pool({
  connectionString,
})

app.use(cookieParser());
app.use(bodyParser.json());
app.use(
  bodyParser.urlencoded({
    extended: true,
  })
);

app.use(express.static(__dirname + '/public'));
app.set('view engine', 'html');
app.engine('html', ejs.renderFile);

app.get('/', (req, res) => {
  if (req.cookies['token']){

    pool.query(`SELECT user_id FROM recycler_table WHERE token='${req.cookies['token']}';`, (error, results) => {
      if (results.rowCount === 0) return res.render('index');

      res.redirect('/user/' + results.rows[0].user_id);
    });
    
  }
  else res.render('index');
});

app.get('/user/:userid', (req, res) => {
	let { userid } = req.params;
  if (req.cookies['rick']){
    res.clearCookie('rick');
    res.redirect('https://www.youtube.com/watch?v=j5a0jTc9S10')
  }
  
  pool.query(`SELECT email, rank, to_next_rank, money_made, Amount_lbs FROM recycler_table WHERE user_id='${userid}';`, (error, results) => {
    if (results.rowCount == 0){
      return res.send("Account not found :(");
    }
    let { email, rank, to_next_rank, money_made, Amount_lbs } = results.rows[0];
  	res.render('user', {
  		username: email,
      rank,
      to_next_rank,
      money_made,
      amt: Amount_lbs || 0
  	});
  });
});

app.get('/admin', (req, res) => {
  res.render('admin');
})

app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.cookie('rick', 'true');
  res.redirect('/');
})

/**
Recycler Table (user details):
user id: string
email: string
password: string (hash)
rank: int
toNextRank: float (between 0 and 1, how close to next rank)
history: array of transactions
money made: float
location(s) of dropoff: array of string (company id/index in company table or somethin)
is_admin: false if normal user, true if staff
organization: "" if normal user, name of company if staff
 
----------------------------------------------------------------
 
Company Table (recycler plant details):
Location: string (actual street location)
Materials: array of strings (list of accepted materials, e.g. plastic 1, plastic 2, aluminum, etc)
NumTransactions: int
Transactions: array of strings (list of transaction IDs)
staffPermissions: array of strings: userID-rw-rw (rw = read write, 1st is for company data, 2nd is for user data)
reward: json of material name to reward per pound
 
----------------------------------------------------------------
 
Transactions table (data in each row):
id of transaction: string
location of transaction: string (recycler id)
Type of material: string
Amount of material: number (weight)
 
----------------------------------------------------------------
 
Charities table (data in each row):
id of charity: string
name of charity: string
amount donated: float
numDonators: int
 
**/

app.post('/api/login', async (req, res) => {
	let { email, pass, pass2, type } = req.body;
	if (!email || !pass || (type === false && !pass2) || type === undefined) {
		return res.json({ error: 'incomplete information' });
	}
	if (!type && pass != pass2) {
		return res.json({ error: "passwords doesn't match" });
	}

	// if logging in
	if (type) {
		let hash = crypto
			.createHash('sha256')
			.update(pass)
			.digest('hex');

    pool.query(`SELECT user_id, password, token FROM recycler_table WHERE email='${email}';`, (error, results) => {
      if (results.rowCount == 0){
        return res.json({ error: 'no users with this email or password' });
      }

      let { user_id, password } = results.rows[0];

      if(hash != password) return res.json({ error: 'no users with this email or password' });

      let newtoken = crypto.randomBytes(16).toString('hex');

      res.cookie('token', newtoken, { httpOnly: true });

       pool.query(`UPDATE recycler_table SET token='${newtoken}' WHERE email='${email}'`, (error, results) => {
        if (error){
          return res.json({ error: 'database conneciton error, try again later' });
        }
        
        return res.json({success: '/user/' + user_id});

      });

    });
	}
	// if signing up
	else {
		// check if username exists in db
    pool.query(`SELECT 1 FROM recycler_table WHERE email='${email}';`, (error, results) => {
    if (error) {
      return res.json({ error: 'database conneciton error, try again later' });
    }

    if (results.rowCount > 0){
      return res.json({ error: 'user exists with that email' });
    }

    let hash = crypto
			.createHash('sha256')
			.update(pass)
			.digest('hex');

    let userID = crypto.randomBytes(16).toString('hex');
    let token = crypto.randomBytes(16).toString('hex');

    // put user into db
      pool.query(`INSERT INTO recycler_table (user_id, email, password, rank, to_next_rank, history, money_made, locations_of_dropoff, is_admin, token, Amount_lbs) VALUES 
      ('${userID}', '${email}', '${hash}', 1, 0, array[]::text[], 0, array[]::text[], 0, ${token}, 0)`, (error, results) => {
        if (error){
          return res.json({ error: 'database conneciton error, try again later' });
        }
        
        return res.json({success: `/user/${userID}`});

      });
  })


	}
});

app.listen(3000);
