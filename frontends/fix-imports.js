const fs = require('fs')
const path = require('path')

// 1️⃣ Fix all imports from '@/src/...' to '@/...'
function fixSrcImports(dir) {
  const files = fs.readdirSync(dir)
  files.forEach(file => {
    const fullPath = path.join(dir, file)
    const stat = fs.statSync(fullPath)

    if (stat.isDirectory()) {
      fixSrcImports(fullPath)
    } else if (file.endsWith('.ts') || file.endsWith('.tsx')) {
      let content = fs.readFileSync(fullPath, 'utf8')
      const newContent = content.replace(/from ['"]@\/src\//g, "from '@/")
      if (newContent !== content) {
        fs.writeFileSync(fullPath, newContent)
        console.log(`Fixed imports in ${fullPath}`)
      }
    }
  })
}

// 2️⃣ Check that required files exist
const requiredFiles = [
  'src/components/ui/progress.tsx',
]

requiredFiles.forEach(f => {
  const filePath = path.join(__dirname, f)
  if (!fs.existsSync(filePath)) {
    console.warn(`⚠️ Missing file: ${filePath}`)
  }
})

// 3️⃣ Ensure axios is in dependencies
const packageJsonPath = path.join(__dirname, 'package.json')
const pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'))

if (!pkg.dependencies) pkg.dependencies = {}
if (!pkg.dependencies.axios && pkg.devDependencies?.axios) {
  pkg.dependencies.axios = pkg.devDependencies.axios
  delete pkg.devDependencies.axios
  fs.writeFileSync(packageJsonPath, JSON.stringify(pkg, null, 2))
  console.log('Moved axios from devDependencies to dependencies')
} else if (!pkg.dependencies.axios) {
  console.warn('⚠️ axios is missing in dependencies! Run: npm install axios')
}

fixSrcImports(path.join(__dirname, 'src'))

console.log('✅ Done! Now rebuild Docker.')
