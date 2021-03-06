const Sauce = require('../models/Sauce');
const fs = require('fs');

exports.defineLikeStatus = (req, res, next) => {  
  switch(req.body.like) {
    case 1:
      Sauce.updateOne({ _id: req.params.id }, { $inc: { likes: 1}, $push: { usersLiked: req.body.userId }, _id: req.params.id })
    .then(
    () => {
      res.status(200).json({
        message: 'Sauce liked successfully !'
      });
    }
    )
    .catch(
      (error) => {
        res.status(400).json({
          error: error
        });
      }
    );
    break;
    case -1:
      Sauce.updateOne({ _id: req.params.id }, { $inc: { dislikes: 1}, $push: { usersDisliked: req.body.userId }, _id: req.params.id })
      .then(
        () => {
          res.status(200).json({ message: 'Sauce disliked'});
        }
      )
      .catch(
        (error) => {
          res.status(404).json({
            error: error
          })
        }
      )
    break;
    case 0:
      Sauce.findOne({ _id : req.params.id })
      .then(
        (sauce) => {
          if(sauce.usersLiked.includes(req.body.userId)) {
            sauce.update( { $inc: { likes: -1}, $pull: { usersLiked: req.body.userId }, _id: req.params.id } )
            .then(
              () => {
                res.status(200).json({ message: 'Like canceled'});
              }
            )
            .catch(
              (error) => {
                res.status(400).json({
                  error: error
                })
              }
            )
          } else if(sauce.usersDisliked.includes(req.body.userId)) {
            sauce.update({ $inc: { dislikes: -1}, $pull: { usersDisliked: req.body.userId }, _id: req.params.id })
            .then(
              () => {
                res.status(200).json({ message: 'Dislike canceled'});
              }
            )
            .catch(
              (error) => {
                res.status(400).json({
                  error: error
                })
              }
            )
          }
        }
      )
      .catch(
        (error) => {
          res.status(404).json({
            error: error
          })
        }
      )
  }
}


exports.createSauce = (req, res, next) => {
        const sauceObject = JSON.parse(req.body.sauce);
        delete sauceObject._id;
        const sauce = new Sauce({
          ...sauceObject,
          imageUrl: `${req.protocol}://${req.get('host')}/images/${req.file.filename}`
        });
    sauce.save()
    .then(
        () => {
            res.status(201).json({
              message: 'Sauce saved successfully!'
            });
          }
    )
    .catch(
        (error) => {
            res.status(400).json({
              error: error
            });
          }
    )
}

exports.getOneSauce = (req, res, next) => {
    Sauce.findOne({
        _id : req.params.id
    })
    .then(
        (sauce) => {
            res.status(200).json(sauce);
        }
    )
    .catch(
        (error) => {
            res.status(404).json({
              error: error
            });
          }
    );
};

exports.updateSauce = (req, res, next) => {
  const sauceObject = req.file ?
  {
    ...JSON.parse(req.body.sauce),
    imageUrl: `${req.protocol}://${req.get('host')}/images/${req.file.filename}`
  } : { ...req.body };
  Sauce.findOne({ _id: req.params.id })
  .then(sauce => {
    const filename = sauce.imageUrl.split('/images/')[1];
    fs.unlink(`images/${filename}`, () => {
      Sauce.updateOne({ _id: req.params.id }, { ...sauceObject, _id: req.params.id })
      .then(
        () => res.status(200).json({ message: 'Objet modifi?? !'}))
      .catch(
        (error) => res.status(400).json({ error }));
    })
  })
  .catch(error => res.status(500).json({ error }));
};



exports.deleteSauce = (req, res, next) => {
    Sauce.findOne({ _id: req.params.id })
      .then(sauce => {
        const filename = sauce.imageUrl.split('/images/')[1];
        fs.unlink(`images/${filename}`, () => {
          Sauce.deleteOne({ _id: req.params.id })
            .then(() => res.status(200).json({ message: 'Objet supprim?? !'}))
            .catch(error => res.status(400).json({ error }));
        });
      })
      .catch(error => res.status(500).json({ error }));
  };

exports.getAllSauces = (req, res, next) => {
    Sauce.find()
    .then(
        (sauces) => {
            res.status(200).json(sauces);
        }
    )
    .catch(    
        (error) => {
        res.status(404).json({
          error: error
        });
      }
    );
};
