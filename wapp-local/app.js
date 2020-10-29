const express = require('express')
const Wappalyzer = require('wappalyzer')

const PORT = 3000

const app = express()


app.get('/', (req, res) => {
  res.send('Wappalyzer API is ready! 🚀')
})

app.get('/extract', (req, res) => {
  let url = req.query.url

  if (url == undefined || url == '') {
    res.status(400).send('missing url query parameter')
    return
  }

	const options = {
  debug: false,
  delay: 500,
  headers: {},
  maxDepth: 3,
  maxUrls: 10,
  maxWait: 5000,
  probe: true,
  userAgent: 'Wappalyzer',
  htmlMaxCols: 2000,
  htmlMaxRows: 2000,
};

;(async function() {
  const wappalyzer = await new Wappalyzer(options)

  try {
    await wappalyzer.init()

    // Optionally set additional request headers
    const headers = {}

    const site = await wappalyzer.open(url, headers)

    // Optionally capture and output errors
    site.on('error', console.error)

    const results = await site.analyze()
	  console.log(results)

    res.send(JSON.stringify(results, null, 2))
  } catch (error) {
    console.error(error)
  }

  await wappalyzer.destroy()
})()
})

app.listen(PORT, () => console.log(`Starting Wappalyzer on http://0.0.0.0:${PORT}`))
